from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from pathlib import Path
import logging
import concurrent.futures

BLOCK_SIZE = 16
BLOCK_MULTIPLIER = 100

def encryptFile(filePath, password):
    try:
        logging.info("Started encoding: " + filePath.resolve().as_posix())
        hashObj = SHA256.new(password.encode('utf-8'))
        hkey = hashObj.digest()
        with open(filePath, "rb") as input_file, open(filePath.resolve().as_posix() +".enc", "ab") as output_file:
            content = b''
            content = input_file.read(BLOCK_SIZE*BLOCK_MULTIPLIER)
            
            while content != b'':       
                output_file.write(encrypt(hkey, content))
                content = input_file.read(BLOCK_SIZE*BLOCK_MULTIPLIER)

            logging.info("Encoded " + filePath.resolve().as_posix())
    except Exception as e:

        print(e)

def decryptFile(filePath, password):
    logging.info("Started decoding: " + filePath.resolve().as_posix())
    try:
        hashObj = SHA256.new(password.encode('utf-8'))
        hkey = hashObj.digest()
        with filePath.open("rb") as input_file, open(filePath.resolve().as_posix()[:-4], "ab") as output_file:
            values = input_file.read(BLOCK_SIZE*BLOCK_MULTIPLIER)       
            while values != b'':
                output_file.write(decrypt(hkey, values))
                values = input_file.read(BLOCK_SIZE*BLOCK_MULTIPLIER)
            
        logging.info("Decoded: " + filePath.resolve().as_posix()[:-4])

    except Exception as e:
        print(e)
    
def pad(msg, BLOCK_SIZE, PAD):
    #print("Applied " + str((BLOCK_SIZE - len(msg) % BLOCK_SIZE) % BLOCK_SIZE))
    #print("len: " + str(len(msg)) + "\n")
    return msg + PAD * ((BLOCK_SIZE - len(msg) % BLOCK_SIZE) % BLOCK_SIZE)

def encrypt(key, msg):
    print("Encrypt")
    PAD = b'\0'
    cipher = AES.new(key, AES.MODE_ECB)
    # print("KEY " + str(AES.block_size))
    result = cipher.encrypt(pad(msg, BLOCK_SIZE, PAD))
    return result

def decrypt(key, msg):
    PAD = b'\0'                         
    decipher = AES.new(key, AES.MODE_ECB)
    pt = decipher.decrypt(msg)
    for i in range(len(pt)-1, -1, -1):
        if pt[i] == PAD:
           # print("HIT")
            pt = pt[:i]
        else:
            #print("NAH")
            break
    return pt

def getMaxLen(arr):
    maxLen = 0
    for elem in arr:
        if len(elem) > maxLen:
            maxLen = len(elem)
    return maxLen

def getTargetFiles(fileExtension):
    fileExtensionFormatted = "*."
    if len(fileExtension) == 0:
        fileExtensionFormatted = "*"
    for i in range(0, getMaxLen(fileExtension)):
        formatted = "["
        for extension in  fileExtension:
            if len(extension) > i:
                formatted += extension[i]
        formatted += "]"
        fileExtensionFormatted += formatted
    return fileExtensionFormatted


if __name__ == "__main__":
    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format, level=logging.INFO,
                        datefmt="%H:%M:%S")
    print("(1) - encrypt\n(2) - decrypt")
    mode = int(input("---> "))
    password = input("password: ")
    passwordConfirm = input("confirm password: ")
    if password != passwordConfirm:
        logging.error("Passwords not matching")
        exit()

    if mode == 1:
        fileExtensions = input("Enter file extensions (jpg png ...): ").split()
        fileExtensionFormatted = getTargetFiles(fileExtensions)
        logging.debug("Using " + fileExtensionFormatted)
        filePaths = list(Path(".").rglob(fileExtensionFormatted))
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor: 
            for filePath in filePaths:
                executor.submit(encryptFile, *(filePath, password))
        
    elif mode == 2:
        filePaths = list(Path(".").rglob("*.[eE][nN][cC]"))
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor: 
            for filePath in filePaths:
                executor.submit(decryptFile, *(filePath, password))
        

