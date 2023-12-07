#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import os
import argparse

def caesar_encrypt(in_byte_array,s):
    buf = in_byte_array
    encoded = bytearray([(byte + s) & 0xFF for byte in buf])
    return encoded

def convert_to_csharp_array_str(in_byte_array):
    header = 'byte[] buf = new byte[%d] {' % len(in_byte_array)
    body = ', '.join('0x' + format(x, '02x') for x in in_byte_array)
    end = '};'
    return header + body + end

def convert_to_vb_array_str(in_byte_array):
    header = 'buf = Array('
    body = ''
    counter = 0
    for b in in_byte_array:
        counter += 1
        if counter % 50 == 0:
            body += '_\n'
        body += str(b) + ', '
    end = ')'
    return header + body + end

# shellcode raw file

parser = argparse.ArgumentParser()
parser.add_argument("raw_shellcode_file")
parser.add_argument("-o", "--output", help="Output to encrypted raw shellcode", default=None)
parser.add_argument("-c", help="Caesar key. Default: 5", default=5)
args = parser.parse_args()

input_raw_file = args.raw_shellcode_file
output_raw_file = args.output
caesar_key = int(args.c)



if os.path.isfile(input_raw_file):
    with open(input_raw_file, 'rb') as f:
        buf = f.read()

if output_raw_file is not None:
    with open(output_raw_file, 'wb') as f:
        f.write(buf)

enc = caesar_encrypt(buf, caesar_key) #

print('Input raw data')
print(buf)

# CSharp
print('Encrypted Csharp format')
output_array = convert_to_csharp_array_str(enc)
print(output_array)

# VB
print('Encrypted VB format')
output_array = convert_to_vb_array_str(enc)
print(output_array)

