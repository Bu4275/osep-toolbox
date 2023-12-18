#!/bin/python3
import argparse
import re
import string
import random
import ad_command_cheat_sheet
import socket
import fcntl
import struct
import re

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
    global varmap
    for k in varmap:
        if varmap[k] is not None and isinstance(varmap[k], str) :
            s = s.replace('{{%s}}' % k, varmap[k])
    
    no_match = re.findall('{{[\w]+}}', s)
    for k in no_match:
        s = s.replace(k, bcolors.WARNING + k + bcolors.ENDC)
    print(s + '\n')
    print('-' * 40)

def replace_to_arsenal(s):
    
    match_list = re.findall('{{([\w_]+)}}', s)
    print(match_list)
    for match in match_list:
        s = s.replace('{{%s}}' % match, '%s<%s>%s' % (bcolors.WARNING, match, bcolors.ENDC))
    print(s)

def print_command(key):
    global varmap
    global command

    command = ad_command_cheat_sheet.command[key]
    if varmap['cmd_os'] is not None:
        os_list = [varmap['cmd_os']]
    else:
        os_list = [x for x in command]
        # print(os_list)

    for cmd_os in os_list:
        if cmd_os in command:


            print_title('[%s] %s' % (cmd_os.capitalize(), key)) # OS [command name]
            s = command[cmd_os]
            if varmap['arsenal']:
                replace_to_arsenal(s)
            else:
                replace_and_print(s)
    print('=' * 80)

def print_title(s):
    title_len = len(s) + 10

    print('=' * title_len)
    space = ' ' * (int((title_len)/2 - (len(s)/2)) - 1)
    print('=' + space + s + space + '=')
    print('=' * title_len)

def get_ip_address_by_inet_name(network_interface):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', network_interface[:15])
        )[20:24])
    except OSError as e:
        # print('Network interface %s not found' % network_interface.decode('utf-8'))
        pass
    return None
        

parser = argparse.ArgumentParser()
parser.add_argument('-c', action='store', metavar='command', help='Choose command number or command name.', default=None)
parser.add_argument('-domain', action='store', metavar='Domain', help='Domain')
parser.add_argument('-domain-sid', action='store', metavar='Domain SID', help='Current domain sid')
parser.add_argument('-u','-username', action='store', metavar='username', help='username')
parser.add_argument('-p','-passowrd',action='store', metavar='password', help='password')

parser.add_argument('-hashes', action='store', metavar='LM:NTLM', help='LM:NTLM')
parser.add_argument('-nthash', action='store', metavar='NTLM', help='NTLM')
parser.add_argument('-krbtgt-nthash', action='store', metavar='Krbtgt NTLM', help='Krbtgt NTLM')
parser.add_argument('-parent-krbtgt-nthash', action='store', metavar='Root domain Krbtgt NTLM', help='Root domain Krbtgt NTLM')
parser.add_argument('-hostname', action='store', metavar='target', help='Hostname')
parser.add_argument('-cmd', action='store', metavar='command', help='command')
parser.add_argument('-target-computer', action='store', metavar='target-computer', help='Target-computer')
parser.add_argument('-target-sid', action='store', metavar='target domain sid', help='Target domain sid')
parser.add_argument('-target-user', action='store', metavar='target-user', help='Target-user')
parser.add_argument('-ud-computer', action='store', metavar='Unconstrained Delegation', help='Unconstrained Delegation')
parser.add_argument('-ud-nthash', action='store', metavar='Unconstrained Delegation Computer NTLM', help='Unconstrained Delegation Computer NTLM')
parser.add_argument('-cd-computer', action='store', metavar='Constrained Delegation computer', help='Constrained Delegation computer')
parser.add_argument('-cd-username', action='store', metavar='Constrained Delegation account', help='Constrained Delegation account')
parser.add_argument('-cd-password', action='store', metavar='Constrained Delegation password', help='Constrained Delegation password')
parser.add_argument('-spn', action='store', metavar='SPN', help='SPN')
parser.add_argument('-attackerhost', action='store', metavar='Attacker Host', help='Attacker Host')
parser.add_argument('-service', action='store', metavar='Service name', help='Service name')


parser.add_argument('-target-domain', action='store', metavar='Target domain', help='Target domain.')
parser.add_argument('-target-dc-host', action='store', metavar='Target dc FQDN', help='Hostname of the target domain controller.')
parser.add_argument('-target-domain-sid', action='store', metavar='Target domain SID', help='Target Domain SID')
parser.add_argument('-current-domain', action='store', metavar='Current domain', help='Current domain.')
parser.add_argument('-current-dc-host', action='store', metavar='Current dc FQDN', help='Hostname of the current domain controller.')
parser.add_argument('-current-domain-sid', action='store', metavar='Current domain SID', help='Current Domain SID')
parser.add_argument('-current-domain-krbtgt-nthash', action='store', metavar='Current domain krbtgt nthash', help='Current domain krbtgt nthash')

parser.add_argument('-forest-domain', action='store', metavar='Target forest domain', help='Target forest domain')
parser.add_argument('-forest-dc-host', action='store', metavar='DC Hostname of target forest', help='DC Hostname of target forest')
parser.add_argument('-forest-extra-sid', action='store', metavar='Forest extra sid', help='Forest extra sid')

parser.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller.')
parser.add_argument('-dc-host', action='store', metavar='ip address', help='Hostname of the domain controller.')
parser.add_argument('-dns-ip', action='store', metavar='DNS IP', help='IP Address of the DNS.')
parser.add_argument('-kali-ip', action='store', metavar='Attacker\'s IP', help='Attacker\'s IP')

parser.add_argument('-extra-sid', action='store', metavar='domain', help='Current domain sid')


parser.add_argument('-trust-key', action='store', metavar='Trusted key', help='Trusted_key')
parser.add_argument('-trust-account', action='store', metavar='Trusted key', help='Trust account. (e.g. corp1.com trust account is corp1$)')
parser.add_argument('-save-path', action='store', metavar='Save path', help='Save path')
parser.add_argument('-ticket', action='store', metavar='Save path', help='kribi ticket or ccache ticket')
parser.add_argument('-cmd-os', action='store', metavar='Save path', help='windows or linux', default=None)


parser.add_argument('-sqlserver', action='store', metavar='MSSQL Server', help='MSSQL Server', default=None)
parser.add_argument('-link-sqlserver', action='store', metavar='Link MSSQL Server', help='Link MSSQL Server', default=None)
parser.add_argument('-link-second', action='store', metavar='Second link MSSQL Server', help='Second link MSSQL Server', default=None)

parser.add_argument('-listen-ip', action='store', metavar='Listen IP', help='Listen IP', default=None)
parser.add_argument('-listen-port', action='store', metavar='Listen Port', help='Listen Port', default='80')
parser.add_argument('-listen-interface', action='store', metavar='Listen interface', help='Listen interface', default='tun0')
parser.add_argument('-filename', action='store', metavar='Filename', help='Filename')
parser.add_argument('-arsenal', action='store_true', default=False, help='Convert to Arsenal')

parser.add_argument('-aes-key', action='store', metavar='aes256-cts-hmac-sha1-96', help='aes256-cts-hmac-sha1-96 for account')
args = parser.parse_args()
varmap = vars(args)
varmap['mimikatz'] = 'Mimikatz.exe'
varmap['rubeus'] = 'Invoke-Rubeus'
varmap['username'] = varmap['u']
varmap['password'] = varmap['p']

if varmap['extra_sid'] is not None:
    if len(varmap['extra_sid'].split('-')) < 8: # Example: S-1-5-21-3759240818-3619593844-2110795065
        varmap['extra_sid'] = varmap['extra_sid'] + '-519'

if varmap['domain'] is not None:
    varmap['domain_short'] = varmap['domain'].split('.')[0]


if varmap['listen_ip'] is None:
    varmap['listen_ip'] = get_ip_address_by_inet_name(varmap['listen_interface'].encode('utf-8'))

current_ip = get_ip_address_by_inet_name(b'tun0')

command_list = [x for x in ad_command_cheat_sheet.command]



index = 0
if varmap['c'] is None:
    for c in command_list:
        print('%d. %s' % (index, c))
        index += 1
elif varmap['c'] == 'all':
    for c in command_list:
        print_command(c)
elif varmap['c'].isdigit():
    c = list(ad_command_cheat_sheet.command)[int(varmap['c'])]
    print_command(c)
else:
    for c in command_list:
        # fuzzy search
        if varmap['c'].lower() in c.lower():
            print_command(c)
