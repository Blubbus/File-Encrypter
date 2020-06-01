# File Encypher
Simple python program to decrypt and encrypt files.

Especially large amount of same file types are nice to decrypt.

It's mostly for practising python programming and working with GitHub and not intended to use.

Can be used by directly opening or with commandline arguments. Execute with -h for more info

## Installation
```
git clone https://github.com/Blubbus/File-Encrypter.git
cd ./File-Encrypter/
pip install -r requirements.txt
python main.py or python main.py -h
```

## Technologie
The file content is encrypted via **AES ECB** encryption.

The file names via a custom **vigenere** to work with file names.

Every file is encrypted in its own thread.

## Weakness
Big files (e.g. videos) can take multiple minutes depending on the file size.

The AES ECB encryption is not 100% safe.
