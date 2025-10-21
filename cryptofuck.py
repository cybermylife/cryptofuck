#!/usr/bin/env python3

import sys
import base64
import binascii
import urllib.parse
import hashlib
import argparse
import codecs

def text_to_binary(text):
    return ' '.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary):
    binary = binary.replace(' ', '')
    return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))

def text_to_hex(text):
    return text.encode().hex()

def hex_to_text(hex_str):
    return bytes.fromhex(hex_str).decode()

def text_to_base64(text):
    return base64.b64encode(text.encode()).decode()

def base64_to_text(b64_str):
    return base64.b64decode(b64_str).decode()

def text_to_url(text):
    return urllib.parse.quote(text)

def url_to_text(url_str):
    return urllib.parse.unquote(url_str)

def text_to_rot13(text):
    return codecs.encode(text, 'rot13')

def rot13_to_text(text):
    return codecs.decode(text, 'rot13')

def text_to_ascii(text):
    return ' '.join(str(ord(char)) for char in text)

def ascii_to_text(ascii_str):
    return ''.join(chr(int(x)) for x in ascii_str.split())

def text_to_octal(text):
    return ' '.join(oct(ord(char))[2:] for char in text)

def octal_to_text(octal_str):
    return ''.join(chr(int(x, 8)) for x in octal_str.split())

def hash_md5(text):
    return hashlib.md5(text.encode()).hexdigest()

def hash_sha1(text):
    return hashlib.sha1(text.encode()).hexdigest()

def hash_sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()

def hash_sha512(text):
    return hashlib.sha512(text.encode()).hexdigest()

def caesar_cipher(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

def reverse_text(text):
    return text[::-1]

def main():
    parser = argparse.ArgumentParser(description='Cryptofuck - Ultimate encoding/decoding tool')
    parser.add_argument('input', nargs='?', help='Input text to convert')
    parser.add_argument('-t', '--to', choices=['bin', 'hex', 'b64', 'url', 'rot13', 'ascii', 'octal', 'md5', 'sha1', 'sha256', 'sha512', 'caesar', 'reverse'], help='Convert to format')
    parser.add_argument('-f', '--from', dest='from_format', choices=['bin', 'hex', 'b64', 'url', 'rot13', 'ascii', 'octal'], help='Convert from format')
    parser.add_argument('-s', '--shift', type=int, default=13, help='Caesar cipher shift (default: 13)')
    parser.add_argument('-l', '--list', action='store_true', help='List all available formats')
    
    args = parser.parse_args()
    
    if args.list:
        print("Available formats:")
        print("  bin     - Binary")
        print("  hex     - Hexadecimal")
        print("  b64     - Base64")
        print("  url     - URL encoding")
        print("  rot13   - ROT13")
        print("  ascii   - ASCII values")
        print("  octal   - Octal")
        print("  md5     - MD5 hash")
        print("  sha1    - SHA1 hash")
        print("  sha256  - SHA256 hash")
        print("  sha512  - SHA512 hash")
        print("  caesar  - Caesar cipher")
        print("  reverse - Reverse text")
        return
    
    if not args.input:
        parser.print_help()
        return
    
    input_text = args.input
    
    if args.from_format:
        if args.from_format == 'bin':
            input_text = binary_to_text(input_text)
        elif args.from_format == 'hex':
            input_text = hex_to_text(input_text)
        elif args.from_format == 'b64':
            input_text = base64_to_text(input_text)
        elif args.from_format == 'url':
            input_text = url_to_text(input_text)
        elif args.from_format == 'rot13':
            input_text = rot13_to_text(input_text)
        elif args.from_format == 'ascii':
            input_text = ascii_to_text(input_text)
        elif args.from_format == 'octal':
            input_text = octal_to_text(input_text)
    
    if args.to:
        if args.to == 'bin':
            result = text_to_binary(input_text)
        elif args.to == 'hex':
            result = text_to_hex(input_text)
        elif args.to == 'b64':
            result = text_to_base64(input_text)
        elif args.to == 'url':
            result = text_to_url(input_text)
        elif args.to == 'rot13':
            result = text_to_rot13(input_text)
        elif args.to == 'ascii':
            result = text_to_ascii(input_text)
        elif args.to == 'octal':
            result = text_to_octal(input_text)
        elif args.to == 'md5':
            result = hash_md5(input_text)
        elif args.to == 'sha1':
            result = hash_sha1(input_text)
        elif args.to == 'sha256':
            result = hash_sha256(input_text)
        elif args.to == 'sha512':
            result = hash_sha512(input_text)
        elif args.to == 'caesar':
            result = caesar_cipher(input_text, args.shift)
        elif args.to == 'reverse':
            result = reverse_text(input_text)
        
        print(result)
    else:
        print("Error: Specify output format with -t/--to")

if __name__ == "__main__":
    main()
