def vigenere_cipher(text, key):
    key = key.lower()
    result = ""
    
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            result += chr((ord(char) + ord(key[i % len(key)]) - 130) % 26 + 65)
        else:
            result += chr((ord(char) + ord(key[i % len(key)]) - 194) % 26 + 97)
            