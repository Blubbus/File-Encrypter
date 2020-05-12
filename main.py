from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from pathlib import Path



def pad(msg, BLOCK_SIZE, PAD):
    return msg.encode('utf-8') + PAD * (BLOCK_SIZE - len(msg) % BLOCK_SIZE)

def encrypt(key, msg):
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
        if pt[i].replace(" ", "") == "":
            continue
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

if __name__ == "__main__":
    print("(1) - encrypt\n(2) - decrypt")
    mode = int(input("---> "))
    if mode == 1:
        password = input("password: ")
        passwordConfirm = input("confirm password: ")
        fileExtension = input("Enter file extensions (jpg png ...): ").split()
        fileExtensionFormatted = "*."
        for i in range(0, getMaxLen(fileExtension)):
            formatted = "["
            for extension in  fileExtension:
                if len(extension) > i:
                    formatted += extension[i]
            formatted += "]"
            fileExtensionFormatted += formatted
        print("Using " + fileExtensionFormatted)
        if password == passwordConfirm:
            hashObj = SHA256.new(password.encode('utf-8'))
            hkey = hashObj.digest()
            result = list(Path(".").rglob(fileExtensionFormatted))
            for paths in result:
                with paths.open("rb") as input_file, open(paths.resolve().as_posix() +".enc", "wb") as output_file:
                    content = ""
                    for byte in input_file.read():
                        content += str(byte) + " "
                    content = content[:-1]
                    encoded = encrypt(hkey, content)
                    output_file.write(encoded)
                    print("Encoded " + paths.resolve().as_posix())
        else:
            print("Passwords not matching!")
            exit()
    
    elif mode == 2:
        password = input("password: ")
        passwordConfirm = input("confirm password: ")
        if password == passwordConfirm:
            hashObj = SHA256.new(password.encode('utf-8'))
            hkey = hashObj.digest()
            result = list(Path(".").rglob("*.[eE][nN][cC]"))
            for paths in result:
                with paths.open("rb") as input_file, open(paths.resolve().as_posix()[:-4], "wb") as output_file:
                    decoded = decrypt(hkey, input_file.read())
                    content = b''
                    #print(decoded)
                    #print("Hier wars")
                    for byte in decoded.split():
                        #print("Byte: ", end="")
                        #print(byte)
                        content += int(byte).to_bytes(1, 'big')
                    output_file.write(content)
                    print("Decoded: " + paths.resolve().as_posix()[:-4])

