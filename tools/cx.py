import sys
import base64
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

def convert_to_csharp_array_str(in_byte_array):
    header = 'byte[] buf = new byte[%d] {' % len(in_byte_array)
    body = ', '.join('0x' + format(x, '02x') for x in in_byte_array)
    end = '};'
    return header + body + end


CAESAR_NUM = 5  # hardcoded "-5" in template
XOR_KEY ='rilak'
cxencoder = CxEncoder(CAESAR_NUM, XOR_KEY)
filename = sys.argv[1]

buf = open(sys.argv[1], 'rb').read()
print(base64.b64encode(buf))
print(base64.b64encode(cxencoder.cxencode(buf)))