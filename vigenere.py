global ALPHABET
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.1234567890"

def generateKey(length, key):
    retKey = str()
    for i in range(length):
        retKey += key[i % len(key)]
    return retKey

def encrypt(msg, key):
    key = generateKey(len(msg), key)
    ciphertext = "E"
    for index, char in enumerate(msg):
        ciphertext += ALPHABET[(ALPHABET.find(key[index]) + ALPHABET.find(char)) % len(ALPHABET)]
    return ciphertext    

def decrypt(ciphertext, key):
    key = generateKey(len(ciphertext), key)
    msg = str()
    ciphertext = ciphertext[1:]
    for index, char in enumerate(ciphertext):
        msg += ALPHABET[(ALPHABET.find(char) - ALPHABET.find(key[index])) % len(ALPHABET)]
    return msg    
