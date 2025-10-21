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
    if len(sys.argv) < 4:
        print("Usage: cryptofuck <input> -<from_format> -<to_format>")
        print("Formats: text, bin, hex, b64, url, rot13, ascii, octal, md5, sha1, sha256, sha512, caesar, reverse")
        print("Examples:")
        print("  cryptofuck nalamo -text -bin")
        print("  cryptofuck 01101110 -bin -text")
        print("  cryptofuck hello -text -hex")
        return
    
    input_text = sys.argv[1]
    from_format = sys.argv[2].lstrip('-')
    to_format = sys.argv[3].lstrip('-')
    
    if from_format == 'text':
        processed_text = input_text
    elif from_format == 'bin':
        processed_text = binary_to_text(input_text)
    elif from_format == 'hex':
        processed_text = hex_to_text(input_text)
    elif from_format == 'b64':
        processed_text = base64_to_text(input_text)
    elif from_format == 'url':
        processed_text = url_to_text(input_text)
    elif from_format == 'rot13':
        processed_text = rot13_to_text(input_text)
    elif from_format == 'ascii':
        processed_text = ascii_to_text(input_text)
    elif from_format == 'octal':
        processed_text = octal_to_text(input_text)
    else:
        print(f"Unknown from format: {from_format}")
        return
    
    if to_format == 'text':
        result = processed_text
    elif to_format == 'bin':
        result = text_to_binary(processed_text)
    elif to_format == 'hex':
        result = text_to_hex(processed_text)
    elif to_format == 'b64':
        result = text_to_base64(processed_text)
    elif to_format == 'url':
        result = text_to_url(processed_text)
    elif to_format == 'rot13':
        result = text_to_rot13(processed_text)
    elif to_format == 'ascii':
        result = text_to_ascii(processed_text)
    elif to_format == 'octal':
        result = text_to_octal(processed_text)
    elif to_format == 'md5':
        result = hash_md5(processed_text)
    elif to_format == 'sha1':
        result = hash_sha1(processed_text)
    elif to_format == 'sha256':
        result = hash_sha256(processed_text)
    elif to_format == 'sha512':
        result = hash_sha512(processed_text)
    elif to_format == 'caesar':
        result = caesar_cipher(processed_text, 13)
    elif to_format == 'reverse':
        result = reverse_text(processed_text)
    else:
        print(f"Unknown to format: {to_format}")
        return
    
    print(result)

if __name__ == "__main__":
    main()
