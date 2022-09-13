#!/usr/bin/env python3

from cryptography.fernet import Fernet

def encrypt():
    # key generatioin
    key = Fernet.generate_key()

    # store the key in a file
    with open('filekey.key', 'wb') as filekey:
        filekey.write(key)

    # using the generated key
    fernet = Fernet(key)

    # opening the file to encrypt (needs to exist!)
    with open('mytext.txt', 'rb') as file:
        original = file.read()

    # encrypting the file
    encrypted = fernet.encrypt(original)

    # opening the file in write mode and
    # writing the encrypted data
    with open('mytextENC.txt', 'wb') as encrypted_file:
        encrypted_file.write(encrypted)


if __name__ == '__main__':
   encrypt()