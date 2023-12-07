import hashlib,binascii
import sys

password = sys.argv[1]
hash = hashlib.new('md4', password.encode('utf-16le')).digest()
print(binascii.hexlify(hash).decode('ascii'))
