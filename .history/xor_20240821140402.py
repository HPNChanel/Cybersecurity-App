def xor_cipher(text, key):
    result = ""
    
    for char in text:
        result += chr(ord(char) ^ key)
    
    return result