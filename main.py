from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from pathlib import Path
import logging
import concurrent.futures
import vigenere

BLOCK_SIZE = 16
BLOCK_MULTIPLIER = 100

def encryptFile(filePath, password):
    try:
        logging.info("Started encoding: " + filePath.resolve().as_posix())
        hashObj = SHA256.new(password.encode('utf-8'))
        hkey = hashObj.digest()
        encryptPath = Path(filePath.parent.resolve().as_posix() + "/" + vigenere.encrypt(filePath.name, password) + ".enc")
        if encryptPath.exists():
            encryptPath.unlink()
        with open(filePath, "rb") as input_file, encryptPath.open("ab") as output_file:
            content = b''
            content = input_file.read(BLOCK_SIZE*BLOCK_MULTIPLIER)
            
            while content != b'':       
                output_file.write(encrypt(hkey, content))
                content = input_file.read(BLOCK_SIZE*BLOCK_MULTIPLIER)

            logging.info("Encoded " + filePath.resolve().as_posix())
            logging.info("To " +encryptPath.resolve().as_posix())
    except Exception as e:
        print(e)

def decryptFile(filePath, password):
    logging.info("Started decoding: " + filePath.resolve().as_posix())
    try:
        hashObj = SHA256.new(password.encode('utf-8'))
        hkey = hashObj.digest()
        decryptFilePath = Path(filePath.parent.resolve().as_posix() + "/" + vigenere.decrypt(filePath.name, password)[:-4])
        with filePath.open("rb") as input_file, decryptFilePath.open("ab") as output_file:
            values = input_file.read(BLOCK_SIZE*BLOCK_MULTIPLIER)       
            while values != b'':
                output_file.write(decrypt(hkey, values))
                values = input_file.read(BLOCK_SIZE*BLOCK_MULTIPLIER)
            
        logging.info("Decoded: " + filePath.resolve().as_posix()[:-4])
        logging.info("TO: " + decryptFilePath.resolve().as_posix() )

    except Exception as e:
        print(e)
    
def pad(msg, BLOCK_SIZE, PAD):
    return msg + PAD * ((BLOCK_SIZE - len(msg) % BLOCK_SIZE) % BLOCK_SIZE)

def encrypt(key, msg):
    PAD = b'\0'
    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.encrypt(pad(msg, BLOCK_SIZE, PAD))
    return result

def decrypt(key, msg):
    PAD = b'\0'                         
    decipher = AES.new(key, AES.MODE_ECB)
    pt = decipher.decrypt(msg)
    for i in range(len(pt)-1, -1, -1):
        if pt[i] == PAD:
            pt = pt[:i]
        else:
            break
    return pt

def getMaxLen(arr):
    maxLen = 0
    for elem in arr:
        if len(elem) > maxLen:
            maxLen = len(elem)
    return maxLen

def getTargetFiles(fileExtension):
    fileExtensions = []
    if len(fileExtension) == 0:
        fileExtensions.append("*")
    else:
    	for Extension in fileExtension:
    		fileExtensionFormatted = "*."
    		for char in Extension:
    			fileExtensionFormatted += "[" + char + "]"
    		fileExtensions.append(fileExtensionFormatted)

    return fileExtensions


if __name__ == "__main__":
    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format, level=logging.INFO,
                        datefmt="%H:%M:%S")
    print("(1) - encrypt\n(2) - decrypt\n(3) - remove .enc files\n(4) - remove other files")
    mode = int(input("---> "))
    password = str()
    passwordConfirm = str()

    if mode == 1 or mode == 2:
        password = input("password: ")
        passwordConfirm = input("confirm password: ")
        
    if password != passwordConfirm:
        logging.error("Passwords not matching")
        exit()

    if mode == 1:
        fileExtensions = input("Enter file extensions (jpg png ...): ").split()
        fileExtensionFormatted = getTargetFiles(fileExtensions)
        filePaths = []
        for fileExtension in fileExtensionFormatted:
        	filePaths = filePaths + list(Path(".").rglob(fileExtension))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor: 
            for filePath in filePaths:
                executor.submit(encryptFile, *(filePath, password))
        opt = input("Remove unencrypted files (y/n): ")
        if opt.upper()[0] == "Y":
            for filePath in filePaths:
                filePath.unlink()

    elif mode == 2:
        filePaths = list(Path(".").rglob("*.[eE][nN][cC]"))
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor: 
            for filePath in filePaths:
                executor.submit(decryptFile, *(filePath, password))
        opt = input("Remove encrypted files (y/n): ")
        if opt.upper()[0] == "Y":
            for filePath in filePaths:
                filePath.unlink()
    elif mode == 3:
        filePaths = list(Path(".").rglob("*.[eE][nN][cC]"))
        for filePath in filePaths:
                filePath.unlink()

    elif mode == 4:
        fileExtensions = input("Enter file extensions (jpg png ...): ").split()
        fileExtensionFormatted = getTargetFiles(fileExtensions)
        filePaths = []
        for fileExtension in fileExtensionFormatted:
        	filePaths = filePaths + list(Path(".").rglob(fileExtension))  
        for filePath in filePaths:
            filePath.unlink()       
        

