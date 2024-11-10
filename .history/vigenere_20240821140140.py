def vigenere_cipher(text, key):
    key = key.lower()
    result = ""
    
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            result += chr((ord(char) + ord(key)))