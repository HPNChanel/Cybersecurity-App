def vigenere_cipher(text, key):
    key = key.lower()
    result = ""
    
    for i in range(len(text)):
        char = 