#!/usr/bin/env python3
import os
import sys
import glob
import subprocess
import random
import datetime
import qrcode
from fastapi import FastAPI, HTTPException, Depends, status, APIRouter
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import uvicorn

BEARER_TOKEN = "test"

g_main_config_src = '.main.config'
g_defclient_config_fn = "_defclient.config"
g_defserver_config = """
[Interface]
#_GenKeyTime = <SERVER_KEY_TIME>
PrivateKey = <SERVER_PRIVATE_KEY>
PublicKey = <SERVER_PUBLIC_KEY>
Address = <SERVER_ADDR>
ListenPort = <SERVER_PORT>
Jc = <JC>
Jmin = <JMIN>
Jmax = <JMAX>
S1 = <S1>
S2 = <S2>
H1 = <H1>
H2 = <H2>
H3 = <H3>
H4 = <H4>

PostUp = iptables -A INPUT -p udp --dport <SERVER_PORT> -m conntrack --ctstate NEW -j ACCEPT --wait 10 --wait-interval 50; iptables -A FORWARD -i <SERVER_IFACE> -o <SERVER_TUN> -j ACCEPT --wait 10 --wait-interval 50; iptables -A FORWARD -i <SERVER_TUN> -j ACCEPT --wait 10 --wait-interval 50; iptables -t nat -A POSTROUTING -o <SERVER_IFACE> -j MASQUERADE --wait 10 --wait-interval 50; ip6tables -A FORWARD -i <SERVER_TUN> -j ACCEPT --wait 10 --wait-interval 50; ip6tables -t nat -A POSTROUTING -o <SERVER_IFACE> -j MASQUERADE --wait 10 --wait-interval 50

PostDown = iptables -D INPUT -p udp --dport <SERVER_PORT> -m conntrack --ctstate NEW -j ACCEPT --wait 10 --wait-interval 50; iptables -D FORWARD -i <SERVER_IFACE> -o <SERVER_TUN> -j ACCEPT --wait 10 --wait-interval 50; iptables -D FORWARD -i <SERVER_TUN> -j ACCEPT --wait 10 --wait-interval 50; iptables -t nat -D POSTROUTING -o <SERVER_IFACE> -j MASQUERADE --wait 10 --wait-interval 50; ip6tables -D FORWARD -i <SERVER_TUN> -j ACCEPT --wait 10 --wait-interval 50; ip6tables -t nat -D POSTROUTING -o <SERVER_IFACE> -j MASQUERADE --wait 10 --wait-interval 50
"""
g_defclient_config = """
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY>
PublicKey = <CLIENT_PUBLIC_KEY>
Address = <CLIENT_TUNNEL_IP>
DNS = 8.8.8.8
Jc = <JC>
Jmin = <JMIN>
Jmax = <JMAX>
S1 = <S1>
S2 = <S2>
H1 = <H1>
H2 = <H2>
H3 = <H3>
H4 = <H4>

[Peer]
AllowedIPs = 0.0.0.0/5, 8.0.0.0/7, 11.0.0.0/8, 12.0.0.0/6, 16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/2, 128.0.0.0/3, 160.0.0.0/5, 168.0.0.0/6, 172.0.0.0/12, 172.32.0.0/11, 172.64.0.0/10, 172.128.0.0/9, 173.0.0.0/8, 174.0.0.0/7, 176.0.0.0/4, 192.0.0.0/9, 192.128.0.0/11, 192.160.0.0/13, 192.169.0.0/16, 192.170.0.0/15, 192.172.0.0/14, 192.176.0.0/12, 192.192.0.0/10, 193.0.0.0/8, 194.0.0.0/7, 196.0.0.0/6, 200.0.0.0/5, 208.0.0.0/4, 8.8.8.8/32
Endpoint = <SERVER_ADDR>:<SERVER_PORT>
PersistentKeepalive = 60
PublicKey = <SERVER_PUBLIC_KEY>
"""

class IPAddr:
    def __init__(self, ipaddr=None):
        self.ip = [0, 0, 0, 0]
        self.mask = None
        if ipaddr:
            self.init(ipaddr)
    def init(self, ipaddr):
        _ipaddr = ipaddr
        if not ipaddr:
            raise RuntimeError(f'ERROR: Incorrect IP-Addr: "{_ipaddr}"')
        if ' ' in ipaddr or ',' in ipaddr:
            raise RuntimeError(f'ERROR: Incorrect IP-Addr: "{_ipaddr}"')
        self.ip = [0, 0, 0, 0]
        self.mask = None
        if '/' in ipaddr:
            self.mask = int(ipaddr.split('/')[1])
            ipaddr = ipaddr.split('/')[0]
        nlist = ipaddr.split('.')
        if len(nlist) != 4:
            raise RuntimeError(f'ERROR: Incorrect IP-addr: "{_ipaddr}"')
        for n, num in enumerate(nlist):
            self.ip[n] = int(num)
    def __str__(self):
        out = f'{self.ip[0]}.{self.ip[1]}.{self.ip[2]}.{self.ip[3]}'
        if self.mask:
            out += '/' + str(self.mask)
        return out

class WGConfig:
    def __init__(self, filename=None):
        self.lines = []
        self.iface = {}
        self.peer = {}
        self.idsline = {}
        self.cfg_fn = None
        if filename:
            self.load(filename)
    def load(self, filename):
        self.cfg_fn = None
        self.lines = []
        self.iface = {}
        self.peer = {}
        self.idsline = {}
        with open(filename, 'r') as file:
            lines = file.readlines()
        iface = None
        secdata_item = None
        secline_item = None
        secdata = []
        secline = []
        for n, line in enumerate(lines):
            line = line.rstrip()
            self.lines.append(line)
            if line.strip() == '':
                continue
            if line.startswith(' ') and not line.strip().startswith('#'):
                raise RuntimeError(f'ERROR_CFG: Incorrect line #{n} into config "{filename}"')
            if line.startswith('#') and not line.startswith('#_'):
                continue
            if line.startswith('[') and line.endswith(']'):
                section_name = line[1:-1]
                if not section_name:
                    raise RuntimeError(f'ERROR_CFG: Incorrect section name: "{section_name}" (#{n+1})')
                secdata_item = {"_section_name": section_name.lower()}
                secline_item = {"_section_name": n}
                if section_name.lower() == 'interface':
                    if iface:
                        raise RuntimeError(f'ERROR_CFG: Found second section Interface in line #{n+1}')
                    iface = secdata_item
                elif section_name.lower() == 'peer':
                    pass
                else:
                    raise RuntimeError(f'ERROR_CFG: Found incorrect section "{section_name}" in line #{n+1}')
                secdata.append(secdata_item)
                secline.append(secline_item)
                continue
            if line.startswith('#_') and ' = ' in line:
                line = line[2:]
            if line.startswith('#'):
                continue
            if ' = ' not in line:
                raise RuntimeError(f'ERROR_CFG: Incorrect line into config: "{line}"  (#{n+1})')
            xv = line.find(' = ')
            if xv <= 0:
                raise RuntimeError(f'ERROR_CFG: Incorrect line into config: "{line}"  (#{n+1})')
            vname = line[:xv].strip()
            value = line[xv+3:].strip()
            if not secdata_item:
                raise RuntimeError(f'ERROR_CFG: Parameter "{vname}" have unknown section! (#{n+1})')
            section_name = secdata_item['_section_name']
            if vname in secdata_item:
                raise RuntimeError(f'ERROR_CFG: Found duplicate of param "{vname}" into section "{section_name}" (#{n+1})')
            secdata_item[vname] = value
            secline_item[vname] = n
        if not iface:
            raise RuntimeError(f'ERROR_CFG: Cannot found section Interface!')
        for i, item in enumerate(secdata):
            line = secline[i]
            peer_name = ""
            if item['_section_name'] == 'interface':
                self.iface = item
                peer_name = "__this_server__"
                if 'PublicKey' not in item:
                    raise RuntimeError(f'ERROR_CFG: Cannot found PublicKey in Interface')
                if 'PrivateKey' not in item:
                    raise RuntimeError(f'ERROR_CFG: Cannot found PrivateKey in Interface')
            else:
                if 'Name' in item:
                    peer_name = item['Name']
                    if not peer_name:
                        raise RuntimeError(f'ERROR_CFG: Invalid peer Name in line #{line["Name"]}')
                elif 'PublicKey' in item:
                    peer_name = item['PublicKey']
                    if not peer_name:
                        raise RuntimeError(f'ERROR_CFG: Invalid peer PublicKey in line #{line["PublicKey"]}')
                else:
                    raise RuntimeError(f'ERROR_CFG: Invalid peer data in line #{line["_section_name"]}')
                if 'AllowedIPs' not in item:
                    raise RuntimeError(f'ERROR_CFG: Cannot found "AllowedIPs" into peer "{peer_name}"')
                if peer_name in self.peer:
                    raise RuntimeError(f'ERROR_CFG: Found duplicate peer with name "{peer_name}"')
                self.peer[peer_name] = item
            if peer_name in self.idsline:
                raise RuntimeError(f'ERROR_CFG: Found duplicate peer with name "{peer_name}"')
            min_line = line['_section_name']
            max_line = min_line
            self.idsline[f'{peer_name}'] = min_line
            for vname in item:
                self.idsline[f'{peer_name}|{vname}'] = line[vname]
                if line[vname] > max_line:
                    max_line = line[vname]
            item['_lines_range'] = (min_line, max_line)
        self.cfg_fn = filename
        return len(self.peer)
    def save(self, filename=None):
        if not filename:
            filename = self.cfg_fn
        if not self.lines:
            raise RuntimeError(f'ERROR: no data')
        with open(filename, 'w', newline='\n') as file:
            for line in self.lines:
                file.write(line + '\n')
    def del_client(self, c_name):
        if c_name not in self.peer:
            raise RuntimeError(f'ERROR: Not found client "{c_name}" in peer list!')
        client = self.peer[c_name]
        ipaddr = client['AllowedIPs']
        min_line, max_line = client['_lines_range']
        del self.lines[min_line:max_line+1]
        del self.peer[c_name]
        secsize = max_line - min_line + 1
        del_list = []
        for k, v in self.idsline.items():
            if v >= min_line and v <= max_line:
                del_list.append(k)
            elif v > max_line:
                self.idsline[k] = v - secsize
        for k in del_list:
            del self.idsline[k]
        return ipaddr
    def set_param(self, c_name, param_name, param_value, force=False, offset=0):
        if c_name not in self.peer:
            raise RuntimeError(f'ERROR: Not found client "{c_name}" in peer list!')
        line_prefix = ""
        if param_name.startswith('_'):
            line_prefix = "#_"
            param_name = param_name[1:]
        client = self.peer[c_name]
        min_line, max_line = client['_lines_range']
        if param_name in client:
            nline = self.idsline[f'{c_name}|{param_name}']
            line = self.lines[nline]
            if line.startswith('#_'):
                line_prefix = "#_"
            self.lines[nline] = f'{line_prefix}{param_name} = {param_value}'
            return
        if not force:
            raise RuntimeError(f'ERROR: Param "{param_name}" not found for client "{c_name}"')
        new_line = f'{line_prefix}{param_name} = {param_value}'
        client[param_name] = param_value
        secsize = max_line - min_line + 1
        if offset >= secsize:
            raise RuntimeError(f'ERROR: Incorrect offset value = {offset} (secsize = {secsize})')
        pos = max_line + 1 if offset <= 0 else min_line + offset
        for k, v in self.idsline.items():
            if v >= pos:
                self.idsline[k] = v + 1
        self.idsline[f'{c_name}|{param_name}'] = pos
        self.lines.insert(pos, new_line)
        return

def exec_cmd(cmd, input=None, shell=True, check=True, timeout=None):
    proc = subprocess.run(cmd, input=input, shell=shell, check=check, timeout=timeout, encoding='utf8', stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    rc = proc.returncode
    out = proc.stdout
    return rc, out

def get_main_iface():
    rc, out = exec_cmd('ip link show')
    if rc:
        raise RuntimeError(f'ERROR: Cannot get net interfaces')
    for line in out.split('\n'):
        if '<BROADCAST' in line and 'state UP' in line:
            xv = line.split(':')
            return xv[1].strip()
    return None

def get_ext_ipaddr():
    rc, out = exec_cmd('curl -4 -s icanhazip.com')
    if rc:
        raise RuntimeError(f'ERROR: Cannot get ext IP-Addr')
    lines = out.split('\n')
    ipaddr = lines[-1] if lines[-1] else lines[-2]
    ipaddr = IPAddr(ipaddr)
    return str(ipaddr)

def gen_pair_keys(cfg_type=None):
    if sys.platform == 'win32':
        return 'client_priv_key', 'client_pub_key'
    if not cfg_type:
        cfg_type = 'WG'
    wgtool = cfg_type.lower()
    rc, out = exec_cmd(f'{wgtool} genkey')
    if rc:
        raise RuntimeError(f'ERROR: Cannot generate private key')
    priv_key = out.strip()
    if not priv_key:
        raise RuntimeError(f'ERROR: Cannot generate private Key')
    rc, out = exec_cmd(f'{wgtool} pubkey', input=priv_key + '\n')
    if rc:
        raise RuntimeError(f'ERROR: Cannot generate public key')
    pub_key = out.strip()
    if not pub_key:
        raise RuntimeError(f'ERROR: Cannot generate public Key')
    return priv_key, pub_key

def get_main_config_path(check=True):
    if not os.path.exists(g_main_config_src):
        raise RuntimeError(f'ERROR: file "{g_main_config_src}" not found!')
    with open(g_main_config_src, 'r') as file:
        lines = file.readlines()
    g_main_config_fn = lines[0].strip()
    cfg_exists = os.path.exists(g_main_config_fn)
    if os.path.basename(g_main_config_fn).startswith('a'):
        cfg_type = 'AWG'
    else:
        cfg_type = 'WG'
    if check and not cfg_exists:
        raise RuntimeError(f'ERROR: Main {cfg_type} config file "{g_main_config_fn}" not found!')
    return g_main_config_fn

class ServerConfigCreate(BaseModel):
    config_filename: str
    ipaddr: str
    port: int
    tun: str = None

class ClientTemplateCreate(BaseModel):
    tmpcfg: str = g_defclient_config_fn
    ipaddr: str = None

class ClientAdd(BaseModel):
    client_name: str
    ipaddr: str = None

class ClientUpdate(BaseModel):
    client_name: str

class ClientDelete(BaseModel):
    client_name: str

class ClientGenerateConfigs(BaseModel):
    tmpcfg: str = g_defclient_config_fn

app = FastAPI(title="WireGuard/AWG Config API", docs_url="/api/docs", redoc_url="/api/redoc", openapi_url="/api/openapi.json")
security = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    if token != BEARER_TOKEN:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return token

router = APIRouter(prefix="/api")

@router.get("/")
def read_root():
    return {"message": "WireGuard/AWG Config API"}

@router.post("/server/create", dependencies=[Depends(verify_token)])
def create_server_config(data: ServerConfigCreate):
    if os.path.exists(data.config_filename):
        raise HTTPException(status_code=400, detail=f'File "{data.config_filename}" already exists!')
    m_cfg_type = 'WG'
    if os.path.basename(data.config_filename).startswith('a'):
        m_cfg_type = 'AWG'
    main_iface = get_main_iface()
    if not main_iface:
        raise HTTPException(status_code=500, detail="Cannot get main network interface!")
    if data.port <= 1000 or data.port > 65530:
        raise HTTPException(status_code=400, detail=f"Incorrect port: {data.port}")
    if not data.ipaddr:
        raise HTTPException(status_code=400, detail="ipaddr is required")
    ip_addr = IPAddr(data.ipaddr)
    if not ip_addr.mask:
        raise HTTPException(status_code=400, detail="ipaddr must include a CIDR mask")
    tun_name = data.tun if data.tun else os.path.splitext(os.path.basename(data.config_filename))[0].strip()
    priv_key, pub_key = gen_pair_keys(m_cfg_type)
    random.seed()
    jc = random.randint(3, 127)
    jmin = random.randint(3, 700)
    jmax = random.randint(jmin + 1, 1270)
    out = g_defserver_config
    out = out.replace('<SERVER_KEY_TIME>', datetime.datetime.now().isoformat())
    out = out.replace('<SERVER_PRIVATE_KEY>', priv_key)
    out = out.replace('<SERVER_PUBLIC_KEY>', pub_key)
    out = out.replace('<SERVER_ADDR>', str(ip_addr))
    out = out.replace('<SERVER_PORT>', str(data.port))
    if m_cfg_type == 'AWG':
        out = out.replace('<JC>', str(jc))
        out = out.replace('<JMIN>', str(jmin))
        out = out.replace('<JMAX>', str(jmax))
        out = out.replace('<S1>', str(random.randint(3, 127)))
        out = out.replace('<S2>', str(random.randint(3, 127)))
        out = out.replace('<H1>', str(random.randint(0x10000011, 0x7FFFFF00)))
        out = out.replace('<H2>', str(random.randint(0x10000011, 0x7FFFFF00)))
        out = out.replace('<H3>', str(random.randint(0x10000011, 0x7FFFFF00)))
        out = out.replace('<H4>', str(random.randint(0x10000011, 0x7FFFFF00)))
    else:
        out = out.replace('\nJc = <', '\n# ')
        out = out.replace('\nJmin = <', '\n# ')
        out = out.replace('\nJmax = <', '\n# ')
        out = out.replace('\nS1 = <', '\n# ')
        out = out.replace('\nS2 = <', '\n# ')
        out = out.replace('\nH1 = <', '\n# ')
        out = out.replace('\nH2 = <', '\n# ')
        out = out.replace('\nH3 = <', '\n# ')
        out = out.replace('\nH4 = <', '\n# ')
    out = out.replace('<SERVER_IFACE>', main_iface)
    out = out.replace('<SERVER_TUN>', tun_name)
    try:
        with open(data.config_filename, 'w', newline='\n') as file:
            file.write(out)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    try:
        with open(g_main_config_src, 'w', newline='\n') as file:
            file.write(data.config_filename)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"message": f"{m_cfg_type} server config file '{data.config_filename}' created!"}

@router.post("/client/template", dependencies=[Depends(verify_token)])
def create_client_template(data: ClientTemplateCreate):
    if os.path.exists(data.tmpcfg):
        raise HTTPException(status_code=400, detail=f'File "{data.tmpcfg}" already exists!')
    ip_str = data.ipaddr
    if not ip_str:
        ext_ip = get_ext_ipaddr()
        ip_str = ext_ip
    ip_obj = IPAddr(ip_str)
    if ip_obj.mask:
        raise HTTPException(status_code=400, detail="ipaddr should not include a mask for server IP")
    out = g_defclient_config
    out = out.replace('<SERVER_ADDR>', str(ip_obj))
    main_config_path = get_main_config_path()
    m_type = 'WG'
    if os.path.basename(main_config_path).startswith('a'):
        m_type = 'AWG'
    if m_type != 'AWG':
        out = out.replace('\nJc = <', '\n# ')
        out = out.replace('\nJmin = <', '\n# ')
        out = out.replace('\nJmax = <', '\n# ')
        out = out.replace('\nS1 = <', '\n# ')
        out = out.replace('\nS2 = <', '\n# ')
        out = out.replace('\nH1 = <', '\n# ')
        out = out.replace('\nH2 = <', '\n# ')
        out = out.replace('\nH3 = <', '\n# ')
        out = out.replace('\nH4 = <', '\n# ')
    try:
        with open(data.tmpcfg, 'w', newline='\n') as file:
            file.write(out)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"message": f"Template client config file '{data.tmpcfg}' created!"}

@router.post("/client/add", dependencies=[Depends(verify_token)])
def add_client(data: ClientAdd):
    main_config_path = get_main_config_path()
    try:
        cfg = WGConfig(main_config_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    srv = cfg.iface
    c_name = data.client_name
    if c_name in cfg.peer:
        raise HTTPException(status_code=400, detail=f"Peer with name '{c_name}' already exists!")
    max_addr = None
    for peer_name, peer in cfg.peer.items():
        if data.ipaddr:
            addr = IPAddr(data.ipaddr)
            addr.mask = None
            if str(addr) == str(IPAddr(peer['AllowedIPs'])):
                raise HTTPException(status_code=400, detail=f"IP address '{data.ipaddr}' already used!")
        addr = IPAddr(peer['AllowedIPs'])
        if not max_addr or addr.ip[3] > max_addr.ip[3]:
            max_addr = addr
    priv_key, pub_key = gen_pair_keys()
    with open(main_config_path, 'r') as file:
        srvcfg = file.read()
    if data.ipaddr:
        ipaddr_str = data.ipaddr
    else:
        if max_addr is None:
            max_addr = IPAddr(srv['Address'])
            max_addr.ip[3] += 1
            max_addr.mask = 32
            ipaddr_str = str(max_addr)
        else:
            max_addr.ip[3] += 1
            ipaddr_str = str(max_addr)
        if max_addr.ip[3] >= 254:
            raise HTTPException(status_code=400, detail="No more free IP addresses available")
    srvcfg += "\n"
    srvcfg += "[Peer]\n"
    srvcfg += f"#_Name = {c_name}\n"
    srvcfg += f"#_GenKeyTime = {datetime.datetime.now().isoformat()}\n"
    srvcfg += f"#_PrivateKey = {priv_key}\n"
    srvcfg += f"PublicKey = {pub_key}\n"
    srvcfg += f"AllowedIPs = {ipaddr_str}\n"
    try:
        with open(main_config_path, 'w', newline='\n') as file:
            file.write(srvcfg)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"message": f"New client '{c_name}' added with IP address '{ipaddr_str}'"}

@router.put("/client/update", dependencies=[Depends(verify_token)])
def update_client(data: ClientUpdate):
    main_config_path = get_main_config_path()
    try:
        cfg = WGConfig(main_config_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    p_name = data.client_name
    try:
        priv_key, pub_key = gen_pair_keys()
        cfg.set_param(p_name, '_PrivateKey', priv_key, force=True, offset=2)
        cfg.set_param(p_name, 'PublicKey', pub_key)
        gentime = datetime.datetime.now().isoformat()
        cfg.set_param(p_name, '_GenKeyTime', gentime, force=True, offset=2)
        cfg.save()
        ipaddr = cfg.peer[p_name]['AllowedIPs']
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"message": f"Keys for client '{p_name}' updated! IP address: '{ipaddr}'"}

@router.delete("/client/delete", dependencies=[Depends(verify_token)])
def delete_client(data: ClientDelete):
    main_config_path = get_main_config_path()
    try:
        cfg = WGConfig(main_config_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    p_name = data.client_name
    try:
        ipaddr = cfg.del_client(p_name)
        cfg.save()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"message": f"Client '{p_name}' deleted! IP address: '{ipaddr}'"}

@router.post("/client/generate_configs", dependencies=[Depends(verify_token)])
def generate_client_configs(data: ClientGenerateConfigs):
    main_config_path = get_main_config_path()
    try:
        cfg = WGConfig(main_config_path)
        srv = cfg.iface
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    if not os.path.exists(data.tmpcfg):
        raise HTTPException(status_code=400, detail=f"Template file '{data.tmpcfg}' not found!")
    with open(data.tmpcfg, 'r') as file:
        tmpcfg = file.read()
    for fn in glob.glob("*.conf"):
        if fn.endswith('awg0.conf'):
            continue
        try:
            os.remove(fn)
        except Exception:
            pass
    for fn in glob.glob("*.png"):
        try:
            os.remove(fn)
        except Exception:
            pass
    random.seed()
    generated_files = []
    for peer_name, peer in cfg.peer.items():
        if 'Name' not in peer or 'PrivateKey' not in peer:
            continue
        jc = random.randint(3, 127)
        jmin = random.randint(3, 700)
        jmax = random.randint(jmin + 1, 1270)
        out = tmpcfg[:]
        out = out.replace('<CLIENT_PRIVATE_KEY>', peer['PrivateKey'])
        out = out.replace('<CLIENT_PUBLIC_KEY>', peer['PublicKey'])
        out = out.replace('<CLIENT_TUNNEL_IP>', peer['AllowedIPs'])
        out = out.replace('<JC>', str(jc))
        out = out.replace('<JMIN>', str(jmin))
        out = out.replace('<JMAX>', str(jmax))
        out = out.replace('<S1>', srv.get('S1', ''))
        out = out.replace('<S2>', srv.get('S2', ''))
        out = out.replace('<H1>', srv.get('H1', ''))
        out = out.replace('<H2>', srv.get('H2', ''))
        out = out.replace('<H3>', srv.get('H3', ''))
        out = out.replace('<H4>', srv.get('H4', ''))
        out = out.replace('<SERVER_PORT>', srv.get('ListenPort', ''))
        out = out.replace('<SERVER_PUBLIC_KEY>', srv.get('PublicKey', ''))
        filename = f'{peer_name}.conf'
        try:
            with open(filename, 'w', newline='\n') as file:
                file.write(out)
            generated_files.append(filename)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    return {"message": "Client configs generated", "files": generated_files}

@router.post("/client/generate_qrcode", dependencies=[Depends(verify_token)])
def generate_qrcode():
    for fn in glob.glob("*.png"):
        try:
            os.remove(fn)
        except Exception:
            pass
    conf_files = glob.glob("*.conf")
    if not conf_files:
        raise HTTPException(status_code=400, detail="Client configs not found!")
    generated_qrcodes = []
    for fn in conf_files:
        if fn.endswith('awg0.conf'):
            continue
        try:
            with open(fn, 'rb') as file:
                conf = file.read().decode('utf8')
            name = os.path.splitext(fn)[0]
            img = qrcode.make(conf)
            img_filename = f'{name}.png'
            img.save(img_filename)
            generated_qrcodes.append(img_filename)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    return {"message": "QR codes generated", "files": generated_qrcodes}

app.include_router(router)

if __name__ == "__main__":
    uvicorn.run("awgapi:app", host="0.0.0.0", port=80, reload=True)
