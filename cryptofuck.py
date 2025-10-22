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

def vigenere_cipher(text, key):
    result = ""
    key = key.upper()
    key_index = 0
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            key_char = ord(key[key_index % len(key)]) - 65
            result += chr((ord(char) - ascii_offset + key_char) % 26 + ascii_offset)
            key_index += 1
        else:
            result += char
    return result

def atbash_cipher(text):
    result = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                result += chr(90 - (ord(char) - 65))
            else:
                result += chr(122 - (ord(char) - 97))
        else:
            result += char
    return result

def rot5_cipher(text):
    result = ""
    for char in text:
        if char.isdigit():
            result += chr((ord(char) - 48 + 5) % 10 + 48)
        else:
            result += char
    return result

def rot47_cipher(text):
    result = ""
    for char in text:
        if 33 <= ord(char) <= 126:
            result += chr((ord(char) - 33 + 47) % 94 + 33)
        else:
            result += char
    return result

def rail_fence_cipher(text, rails):
    if rails <= 1:
        return text
    
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    
    for char in text:
        fence[rail].append(char)
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction = -direction
    
    return ''.join(''.join(rail) for rail in fence)

def rail_fence_decipher(text, rails):
    if rails <= 1:
        return text
    
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    
    for _ in text:
        fence[rail].append(None)
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction = -direction
    
    text_index = 0
    for rail in fence:
        for i in range(len(rail)):
            rail[i] = text[text_index]
            text_index += 1
    
    result = ""
    rail = 0
    direction = 1
    
    for _ in text:
        result += fence[rail].pop(0)
        rail += direction
        if rail == rails - 1 or rail == 0:
            direction = -direction
    
    return result

def morse_code(text):
    morse_dict = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
        '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
        '8': '---..', '9': '----.'
    }
    
    result = ""
    for char in text.upper():
        if char in morse_dict:
            result += morse_dict[char] + " "
        elif char == " ":
            result += "/ "
        else:
            result += char + " "
    return result.strip()

def morse_decode(text):
    morse_dict = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
        '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
        '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
        '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
        '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
        '---..': '8', '----.': '9'
    }
    
    result = ""
    words = text.split(" / ")
    for word in words:
        chars = word.split()
        for char in chars:
            if char in morse_dict:
                result += morse_dict[char]
            else:
                result += char
        result += " "
    return result.strip()

def bacon_cipher(text):
    bacon_dict = {
        'A': 'AAAAA', 'B': 'AAAAB', 'C': 'AAABA', 'D': 'AAABB', 'E': 'AABAA',
        'F': 'AABAB', 'G': 'AABBA', 'H': 'AABBB', 'I': 'ABAAA', 'J': 'ABAAB',
        'K': 'ABABA', 'L': 'ABABB', 'M': 'ABBAA', 'N': 'ABBAB', 'O': 'ABBBA',
        'P': 'ABBBB', 'Q': 'BAAAA', 'R': 'BAAAB', 'S': 'BAABA', 'T': 'BAABB',
        'U': 'BABAA', 'V': 'BABAB', 'W': 'BABBA', 'X': 'BABBB', 'Y': 'BBAAA',
        'Z': 'BBAAB'
    }
    
    result = ""
    for char in text.upper():
        if char in bacon_dict:
            result += bacon_dict[char]
        else:
            result += char
    return result

def bacon_decode(text):
    bacon_dict = {
        'AAAAA': 'A', 'AAAAB': 'B', 'AAABA': 'C', 'AAABB': 'D', 'AABAA': 'E',
        'AABAB': 'F', 'AABBA': 'G', 'AABBB': 'H', 'ABAAA': 'I', 'ABAAB': 'J',
        'ABABA': 'K', 'ABABB': 'L', 'ABBAA': 'M', 'ABBAB': 'N', 'ABBBA': 'O',
        'ABBBB': 'P', 'BAAAA': 'Q', 'BAAAB': 'R', 'BAABA': 'S', 'BAABB': 'T',
        'BABAA': 'U', 'BABAB': 'V', 'BABBA': 'W', 'BABBB': 'X', 'BBAAA': 'Y',
        'BBAAB': 'Z'
    }
    
    result = ""
    for i in range(0, len(text), 5):
        chunk = text[i:i+5]
        if chunk in bacon_dict:
            result += bacon_dict[chunk]
        else:
            result += chunk
    return result

def reverse_text(text):
    return text[::-1]

def show_help():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    CRYPTOFUCK                               ║
║              Ultimate Encoding/Decoding Tool                 ║
╚══════════════════════════════════════════════════════════════╝

USAGE:
   cryptofuck <input> -<from_format> -<to_format>

FORMATS:
   text, bin, hex, b64, url, rot13, ascii, octal
   md5, sha1, sha256, sha512, caesar, reverse
   vigenere, atbash, rot5, rot47, rail, morse, bacon

EXAMPLES:
   cryptofuck nalamo -text -bin
   cryptofuck "01101110 01100001" -bin -text
   cryptofuck hello -text -hex
   cryptofuck password -text -md5
   cryptofuck hello -text -reverse
   cryptofuck "bmFsYW1v" -b64 -text
   cryptofuck "XRPCTCRGNEI" -cesar -text
   cryptofuck hello -text -vigenere -key SECRET
   cryptofuck hello -text -morse

SPECIAL COMMANDS:
   cryptofuck wiki    - Show complete examples
   cryptofuck help    - Show this help
""")

def show_wiki():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    CRYPTOFUCK WIKI                           ║
╚══════════════════════════════════════════════════════════════╝

BINARY CONVERSIONS:
   cryptofuck hello -text -bin
   → 01101000 01100101 01101100 01101100 01101111
   
   cryptofuck "01101000 01100101" -bin -text
   → he

HEXADECIMAL CONVERSIONS:
   cryptofuck hello -text -hex
   → 68656c6c6f
   
   cryptofuck 68656c6c6f -hex -text
   → hello

BASE64 CONVERSIONS:
   cryptofuck hello -text -b64
   → aGVsbG8=
   
   cryptofuck aGVsbG8= -b64 -text
   → hello

URL ENCODING:
   cryptofuck "hello world" -text -url
   → hello%20world
   
   cryptofuck hello%20world -url -text
   → hello world

ROT13:
   cryptofuck hello -text -rot13
   → uryyb
   
   cryptofuck uryyb -rot13 -text
   → hello

ASCII VALUES:
   cryptofuck hello -text -ascii
   → 104 101 108 108 111
   
   cryptofuck "104 101 108 108 111" -ascii -text
   → hello

HASHING:
   cryptofuck password -text -md5
   → 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
   
   cryptofuck password -text -sha256
   → 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8

CAESAR CIPHER:
   cryptofuck hello -text -caesar
   → uryyb
   
   cryptofuck uryyb -caesar -text
   → hello

REVERSE:
   cryptofuck hello -text -reverse
   → olleh

OCTAL:
   cryptofuck hello -text -octal
   → 150 145 154 154 157
   
   cryptofuck "150 145 154 154 157" -octal -text
   → hello
""")


def main():
    if len(sys.argv) < 2:
        show_help()
        return
    
    if sys.argv[1] == "help" or sys.argv[1] == "-h" or sys.argv[1] == "--help":
        show_help()
        return
    
    if sys.argv[1] == "wiki":
        show_wiki()
        return
    
    
    if len(sys.argv) < 4:
        print("Error: Missing arguments!")
        print("Usage: cryptofuck <input> -<from_format> -<to_format>")
        print("Type 'cryptofuck help' for more info")
        return
    
    input_text = sys.argv[1]
    from_format = sys.argv[2].lstrip('-')
    
    # Trouve le format de sortie (peut être après des paramètres)
    to_format = None
    for i in range(3, len(sys.argv)):
        if sys.argv[i].startswith('-') and not sys.argv[i].startswith('--') and sys.argv[i] != '-shift' and sys.argv[i] != '-key' and sys.argv[i] != '-rails':
            to_format = sys.argv[i].lstrip('-')
            break
    
    if not to_format:
        print("Error: Missing output format!")
        print("Usage: cryptofuck <input> -<from_format> -<to_format>")
        return
    
    try:
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
        elif from_format == 'cesar':
            # César nécessite le décalage
            if len(sys.argv) > 4 and sys.argv[4] == '-shift' and len(sys.argv) > 5:
                shift = int(sys.argv[5])
                processed_text = caesar_cipher(input_text, -shift)  # Décoder
            else:
                processed_text = caesar_cipher(input_text, -13)  # ROT13 par défaut
        elif from_format == 'vigenere':
            if len(sys.argv) > 4 and sys.argv[4] == '-key' and len(sys.argv) > 5:
                key = sys.argv[5]
                processed_text = vigenere_cipher(input_text, key)
            else:
                print("Error: Vigenère decipher requires a key. Use: -vigenere -key SECRET")
                return
        elif from_format == 'atbash':
            processed_text = atbash_cipher(input_text)
        elif from_format == 'rot5':
            processed_text = rot5_cipher(input_text)
        elif from_format == 'rot47':
            processed_text = rot47_cipher(input_text)
        elif from_format == 'rail':
            if len(sys.argv) > 4 and sys.argv[4] == '-rails' and len(sys.argv) > 5:
                rails = int(sys.argv[5])
                processed_text = rail_fence_decipher(input_text, rails)
            else:
                processed_text = rail_fence_decipher(input_text, 3)
        elif from_format == 'morse':
            processed_text = morse_decode(input_text)
        elif from_format == 'bacon':
            processed_text = bacon_decode(input_text)
        else:
            print(f"Unknown from format: {from_format}")
            print("Available formats: text, bin, hex, b64, url, rot13, ascii, octal, cesar, vigenere, atbash, rot5, rot47, rail, morse, bacon")
            return
    except Exception as e:
        print(f"Error converting from {from_format}: {str(e)}")
        print("Make sure your input is in the correct format!")
        return
    
    try:
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
        elif to_format == 'vigenere':
            # Vigenère nécessite une clé
            if len(sys.argv) > 4 and sys.argv[4] == '-key' and len(sys.argv) > 5:
                key = sys.argv[5]
                result = vigenere_cipher(processed_text, key)
            else:
                print("Error: Vigenère cipher requires a key. Use: -vigenere -key SECRET")
                return
        elif to_format == 'atbash':
            result = atbash_cipher(processed_text)
        elif to_format == 'rot5':
            result = rot5_cipher(processed_text)
        elif to_format == 'rot47':
            result = rot47_cipher(processed_text)
        elif to_format == 'rail':
            # Rail Fence nécessite le nombre de rails
            if len(sys.argv) > 4 and sys.argv[4] == '-rails' and len(sys.argv) > 5:
                rails = int(sys.argv[5])
                result = rail_fence_cipher(processed_text, rails)
            else:
                result = rail_fence_cipher(processed_text, 3)  # Par défaut 3 rails
        elif to_format == 'morse':
            result = morse_code(processed_text)
        elif to_format == 'bacon':
            result = bacon_cipher(processed_text)
        else:
            print(f"Unknown to format: {to_format}")
            print("Available formats: text, bin, hex, b64, url, rot13, ascii, octal, md5, sha1, sha256, sha512, caesar, reverse, vigenere, atbash, rot5, rot47, rail, morse, bacon")
            return
        
        print(result)
    except Exception as e:
        print(f"Error converting to {to_format}: {str(e)}")
        print("Make sure your input is valid!")
        return

if __name__ == "__main__":
    main()