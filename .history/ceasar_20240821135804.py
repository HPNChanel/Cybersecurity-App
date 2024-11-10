def ceasar_cipher(text, shift):
    result = ""
    
    for i in range(len(text)):
        char = text[i]