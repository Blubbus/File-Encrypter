from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from pathlib import Path
import logging
import concurrent.futures


def encryptFile(filePath, password):
    logging.info("Started encoding: " + filePath.resolve().as_posix())
    hashObj = SHA256.new(password.encode('utf-8'))
    hkey = hashObj.digest()
    with open(filePath, "rb") as input_file, open(filePath.resolve().as_posix() +".enc", "ab") as output_file:
        content = ""
        content = input_file.read(16*100)
        #print(content)
        j = 0
        hand = open("debug.txt", "a")
        while  content != b'':       
            #print("iter")
            i=0
            encoded = ""
            for byte in content:
                if "73" in str(byte) and j==4:
                    print("test")
                encoded += str(byte) + " "
                i+=1
            #encoded = encoded[:-1] # to remove last " "
            
            hand.write(encoded + "\n")
            encoded = encrypt(hkey, encoded)
            output_file.write(encoded)
            #print(content)
            content = input_file.read(16*100)
            j+=1

        logging.info("Encoded " + filePath.resolve().as_posix())

def decryptFile(filePath, password):
    i = 0
    j= 0
    try:
        hashObj = SHA256.new(password.encode('utf-8'))
        hkey = hashObj.digest()
        with filePath.open("rb") as input_file, open(filePath.resolve().as_posix()[:-4], "ab") as output_file:
            values = input_file.read(16*100)
            while values != b'':
                
                print(i)
                i+= 1
                decoded = decrypt(hkey, values)
                content = b''
                hand = open("debug2.txt", "a")
                hand.write(decoded +"\n")
                hand.close()
                for byte in decoded.split():
                    content += int(byte).to_bytes(1, 'big')
                output_file.write(content)
                values = input_file.read(16*100)
                j+= 1
            
        logging.info("Decoded: " + filePath.resolve().as_posix()[:-4])

    except Exception as e:
        print(i)
        print(j)
        print(e)
    
def pad(msg, BLOCK_SIZE, PAD):
    print("Applied " + str((BLOCK_SIZE - len(msg) % BLOCK_SIZE)))
    return msg.encode('utf-8') + PAD * (BLOCK_SIZE - len(msg) % BLOCK_SIZE)

def encrypt(key, msg):
    print("Encrypt")
    BLOCK_SIZE = 16
    PAD = b'\0'
    cipher = AES.new(key, AES.MODE_ECB)
    # print("KEY " + str(AES.block_size))
    result = cipher.encrypt(pad(msg, BLOCK_SIZE, PAD))
    return result

def decrypt(key, msg):
    PAD = b'\0'                         
    decipher = AES.new(key, AES.MODE_ECB)
    pt = decipher.decrypt(msg).decode('utf-8')
    for i in range(len(pt)-1, -1, -1):
        if pt[i].encode('utf-8') == PAD:
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
        

