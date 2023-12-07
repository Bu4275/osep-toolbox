import re
import sys
import subprocess

pipe = subprocess.PIPE
proxychains = 'proxychains -q '

def run_cmd(cmd):
    print('Run: %s' % cmd)
    p = subprocess.Popen(cmd, shell=True, stderr=pipe, stdout=pipe, stdin=pipe)
    while True:
        line = p.stdout.readline()
        if not line: break
        print(line.decode('utf-8'), end="")

def cme(ip, username, password=None, ntlm=None, domain=None, poto=None, useProxy=False):
    global proxychains
    cme_binary = 'crackmapexec '
    if password is None and ntlm is None:
        print('Password and NTLM is None. Choose one.')
        return None
    cmd = cme_binary
    if useProxy:
        cmd = proxychains + cmd
    if domain is None or domain =='':
        domain = '.'

    cmd += f'{proto} {ip} -u {username} -d {domain} '



    if password is not None:
        cmd += f'-p {password} '
    else:
        cmd += f'-H {ntlm} '
    # print(cmd)
    run_cmd(cmd)



if __name__ == '__main__':
    filename = sys.argv[1]
    ips = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            data = line.split(',')
            proto = 'smb'
            ip = data[0]
            domain = data[1]
            username = data[2]
            password = data[3]
            ntlm = data[4]
            useProxy = True if data[5].lower().strip() == 'true' else False
            cme(ip, username, password, ntlm, domain, proto, useProxy)
