
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import base64
import sys

# https://ithelp.ithome.com.tw/articles/10263469
def AESEncrypt(key, iv, data):
    ## new 一個 AES CBC cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    ## 將要加密的 data encode 成 utf-8
    ## 然後使用 pad function 將明文 padding 到 block size
    ## https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Util/Padding.py#L39
    ## 從上面網址可以知道他預設使用 pkcs7 這種 padding 方式，我們不需要做任何事情
    return (cipher.encrypt(pad(data, AES.block_size)))

def AESDecrypt(key, iv, data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    plain = cipher.decrypt(data)
    return cipher.decrypt(data)

aes_key = 'r' * 16
aes_iv = 'r' * 16

with open(sys.argv[1], 'rb') as f:
    data = f.read()
    b64_aes_shellcode = base64.b64encode(AESEncrypt(aes_key.encode('utf-8'), aes_iv.encode('utf-8'), data))
    print(b64_aes_shellcode)