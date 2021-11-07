from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from pathlib import Path
import logging
import concurrent.futures
import sys
import getopt

BLOCK_SIZE = 16
BLOCK_MULTIPLIER = 100

global ALPHABET
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.1234567890"

maxWorker = 10

helpText = '''Usage: python main.py [args] fileExtension fileExtension ...
Arguments:  -r : deletes en- or decrypted files after use
            -m : set mode:  1- encrypt
                            2- decrypt
                            3- deletes encrypted files
                            4- deletes files with extensions if empty everything except .enc and .py
                            5- encrypt one file
            -p : sets password no space allowed
            -w : sets max number of threads
            '''
version = "1.1d"

def generateKey(length, key):
    retKey = str()
    for i in range(length):
        retKey += key[i % len(key)]
    return retKey

def vencrypt(msg, key):
    key = generateKey(len(msg), key)
    ciphertext = "E"
    for index, char in enumerate(msg):
        ciphertext += ALPHABET[(ALPHABET.find(key[index]) + ALPHABET.find(char)) % len(ALPHABET)]
    return ciphertext

def vdecrypt(ciphertext, key):
    key = generateKey(len(ciphertext), key)
    msg = str()
    ciphertext = ciphertext[1:]
    for index, char in enumerate(ciphertext):
        msg += ALPHABET[(ALPHABET.find(char) - ALPHABET.find(key[index])) % len(ALPHABET)]
    return msg

def encryptFile(filePath, password):
    try:
        logging.info("Started encoding: " + filePath.resolve().as_posix())
        hashObj = SHA256.new(password.encode('utf-8'))
        hkey = hashObj.digest()
        encryptPath = Path(filePath.parent.resolve().as_posix() + "/" + vencrypt(filePath.name, password) + ".enc")
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
        decryptFilePath = Path(filePath.parent.resolve().as_posix() + "/" + vdecrypt(filePath.name, password)[:-4])
        if decryptFilePath.exists():
            decryptFilePath.unlink()
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

def generateEncryptThreads(fileExtensions, password, removeFiles, path):
    fileExtensionFormatted = getTargetFiles(fileExtensions)
    filePaths = []
    for fileExtension in fileExtensionFormatted:
        filePaths = filePaths + list(Path(path).rglob(fileExtension))

    with concurrent.futures.ThreadPoolExecutor(max_workers=maxWorker) as executor:
        for filePath in filePaths:
            executor.submit(encryptFile, *(filePath, password))
    if removeFiles:
        for filePath in filePaths:
            filePath.unlink()

def generateDecryptThreads(password, removeFiles, path):
    filePaths = list(Path(path).rglob("*.[eE][nN][cC]"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=maxWorker) as executor:
        for filePath in filePaths:
            executor.submit(decryptFile, *(filePath, password))
    if removeFiles:
        for filePath in filePaths:
            filePath.unlink()

def removeEncryptedFiles(path):
    filePaths = list(Path(path).rglob("*.[eE][nN][cC]"))
    for filePath in filePaths:
            filePath.unlink()

def removeExFiles(fileExtensions, path):
    fileExtensionFormatted = getTargetFiles(fileExtensions)
    filePaths = []
    for fileExtension in fileExtensionFormatted:
        filePaths = filePaths + list(Path(path).rglob(fileExtension))
    for filePath in filePaths:
        filePath.unlink()

if __name__ == "__main__":
    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format, level=logging.INFO,
                        datefmt="%H:%M:%S")
    if len(sys.argv[1:]) < 1:

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
            removeFiles = input("Remove unencrypted files afterwards(Y): ")
            if removeFiles[0].upper() == 'Y':
                removeFiles = True
            else:
                removeFiles = False
            path = input("Select folder to encrypt (\".\" for current dir): ")
            generateEncryptThreads(fileExtensions, password, removeFiles, path)

        elif mode == 2:
            removeFiles = input("Remove encrypted files afterwards(Y): ")
            if removeFiles[0].upper() == 'Y':
                removeFiles = True
            else:
                removeFiles = False
            path = input("Select folder to decrypt (\".\" for current dir): ")

            generateDecryptThreads(password, removeFiles, path)

        elif mode == 3:
            path = input("Select folder for removal (\".\" for current dir): ")

            removeEncryptedFiles(path)

        elif mode == 4:
            fileExtensions = input("Enter file extensions (jpg png ...): ").split()
            path = input("Select folder for removal (\".\" for current dir): ")

            removeExFiles(fileExtensions, path)

    else:
        removeFiles = False
        password = ""
        mode = 0
        opts, args = getopt.getopt(sys.argv[1:], "rm:p:w:vd:h")

        for opt, arg in opts:
            if opt == '-r':
                removeFiles = True
            elif opt == '-m':
                mode = int(arg)
            elif opt == '-w':
                maxWorker = int(arg)
            elif opt == '-p':
                password = arg
            elif opt == '-d':
                path = arg
            elif opt == '-h':
                print(helpText)
                exit()

        if mode == 0 or (password == "" and mode in (1,2,5)):
            print("Missing arguments!\nType -h as argument to get help Page.")
            exit()

        if mode == 1:
            generateEncryptThreads(args, password, removeFiles, path)

        elif mode == 2:
            generateDecryptThreads(password, removeFiles, path)

        elif mode == 3:
            removeEncryptedFiles()

        elif mode == 4:
            # print(args)
            if args == []:
                filePaths = list(Path(path).rglob("*.*"))
                removePaths = list()
                for index, filePath in enumerate(filePaths):
                    if not ".enc" in filePath.name and not ".py" in filePath.name:
                        removePaths.append(filePath)
                try:
                    for removeFilePath in removePaths:
                        removeFilePath.unlink()

                except Exception as e:
                    print(e)

            else:
                removeExFiles(args)

        elif mode == 5:
            encryptFile(Path(args), password)
