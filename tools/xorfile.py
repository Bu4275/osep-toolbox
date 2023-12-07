import sys
import os


def xor(s, key):
    b = bytearray(len(s))
    kb = key.encode('utf-8')
    for i in range(len(s)):
        b[i] = (s[i] ^ kb[i % len(kb)]) & 0xff
    return bytes(b)

def caesar_encrypt(in_byte_array,s):
    return bytearray([(byte - s) & 0xFF for byte in in_byte_array])

with open(sys.argv[1], 'rb') as f:
    data = f.read()
    de_data = caesar_encrypt(data, 11)
    de_data = xor(de_data, 'adwocdmwa')
    print(de_data.decode('utf-8'))
