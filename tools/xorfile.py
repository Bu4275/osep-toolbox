import sys
import os

def xor(s, key):
    b = bytearray(len(s))
    kb = key.encode('ascii')
    for i in range(len(s)):
        b[i] = (s[i] ^ kb[i % len(kb)]) & 0xff
    return bytes(b)

def caesar_encrypt(in_byte_array,s):
    return bytearray([(byte - s) & 0xFF for byte in in_byte_array])

filename = sys.argv[1]
xor_key = sys.argv[2]
output = 'decode_' + filename

with open(filename, 'rb') as f:
    data = f.read()
    de_data = xor(data, xor_key)
    with open(output, 'wb') as fw:
        fw.write(de_data)

print('Save to : %s' % output)

