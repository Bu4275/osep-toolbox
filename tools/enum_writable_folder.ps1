foreach($file_path in Get-Content path.txt){
if(Test-Path -Path $file_path -PathType Container)
    {
        cd $tools
        icacls.exe $file_path | out-file -FilePath permissions.txt -Append
    }
}