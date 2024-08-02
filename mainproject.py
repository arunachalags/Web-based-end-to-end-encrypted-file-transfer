# Encryption And Decryption Software
# Encryption: AES
# UI: Terminal Interface

# Import Necessary Libraries
import os
import random
import string
import time
import sys
import pyAesCrypt
import socket
import hashlib
import getpass
import pyfiglet
from Crypto.Cipher import AES

# Global Variables Initialization
keyFile = ''  # Key File
dencryptionKey = ''  # Key File Contents
bufferSize = 128 * 1024
chunkSize = 16
port = 2221

def longLine():
    print("--------------------------------------------------------------------------------")

def title():
    clear()
    ascii_banner = pyfiglet.figlet_format("SJCIT")
    print(ascii_banner)
    longLine()

def clear():
    os.system("cls")  # Windows clear screen command

# Main Menu
def main():
    title()
    global dencryptionKey
    # If Key Files In Session Print Key File Under Title
    if len(keyFile) > 0:
        print("Key File: " + keyFile)
        with open(keyFile, 'r') as keyFileObject:
            dencryptionKey = keyFileObject.read()
        longLine()
    else:
        dencryptionKey = ''
    print("1) Encrypt A File")
    print("2) Decrypt A File")
    print("3) Send A Secure File Transfer")
    print("4) Receive A Secure File Transfer")
    print("5) Generate A 16 Bit Key")
    print("6) Generate A 64 Bit Key")
    print("7) Generate A 128 Bit Key")
    print("8) Add Key File To Session")
    print("9) Remove Key From Session")
    print("10) Exit")
    longLine()
    option = input("Option: ")
    opTree(option)  # Takes Option And Runs It Through The Operation Handler To Change Screens/Functions

# Option Controller For Main Menu
def opTree(option):
    if option == "1":
        encryptScreen()
    elif option == "2":
        decryptScreen()
    elif option == "3":
        sendFileScreen()
    elif option == "4":
        recieveFileScreen()
    elif option == "5":
        keyGenScreen(16)  # Generates A 16 Bit Key File
    elif option == "6":
        keyGenScreen(64)  # Generates A 64 Bit Key File
    elif option == "7":
        keyGenScreen(128)  # Generates A 128 Bit Key File
    elif option == "8":
        addKeyScreen()
    elif option == "9":
        removeKeyScreen()
    elif option == "10":
        clear()
        exit()
    else:
        main()

def sendFileScreen():
    title()
    rHost = input("Receiver's IP: ")
    fileToSend = input("File To Send: ")
    longLine()
    print("Waiting For Receiver's Confirmation...")
    longLine()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((rHost, port))
        sendConfirm = sock.recv(1)
        if sendConfirm.decode('utf-8') == '1':
            encryptedFileName = os.path.basename(fileToSend) + ".dnc"
            pyAesCrypt.encryptFile(fileToSend, encryptedFileName, dencryptionKey, bufferSize)
            with sock, open(encryptedFileName, 'rb') as f:
                print("Sending File Name")
                longLine()
                sock.sendall((encryptedFileName + '\n').encode())
                time.sleep(0.3)
                print("Sending File Size")
                longLine()
                sock.sendall(f'{os.path.getsize(encryptedFileName)}\n'.encode())
                time.sleep(0.3)
                print("Starting Secure Key Exchange")
                print("Sending Modulo")
                mod = ''.join(str(random.randint(1, 3)) for _ in range(3))
                sock.sendall((mod + '\n').encode())
                time.sleep(0.1)
                print("Sending Base")
                base = ''.join(str(random.randint(1, 3)) for _ in range(3))
                sock.sendall((base + '\n').encode())
                print("Generating Private Key")
                privateKey = ''.join(str(random.randint(1, 5)) for _ in range(5))
                time.sleep(0.3)
                print("Generating Equation")
                senderPublicKey = (int(base) ** int(privateKey)) % int(mod)
                time.sleep(0.1)
                print("Receiving Receiver's Public Key")
                recieverPublicKey = sock.recv(8000).decode('utf-8')
                time.sleep(0.1)
                print("Sending Public Key")
                sock.sendall((str(senderPublicKey) + '\n').encode())
                time.sleep(0.1)
                print("Calculating Key")
                sharedKey = str((int(recieverPublicKey) ** int(privateKey)) % int(mod))
                sharedKey = hashlib.sha256(sharedKey.encode()).hexdigest()[:32]
                print("Encrypting Key")
                initVector = 16 * '\x00'
                encryptor = AES.new(sharedKey.encode('utf-8'), AES.MODE_CBC, initVector.encode('utf-8'))
                encryptedKey = encryptor.encrypt(dencryptionKey.ljust(32).encode('utf-8'))
                time.sleep(0.1)
                print("Sending Encryption Key Size")
                sock.sendall((str(len(encryptedKey)) + '\n').encode())
                time.sleep(0.1)
                print("Sending Encryption Key")
                sock.sendall(encryptedKey)
                time.sleep(0.1)
                print("Secure Key Transfer Complete")
                longLine()
                time.sleep(0.1)
                print("Sending Encrypted File")
                longLine()
                f.seek(0)  # Ensure file pointer is at the beginning
                while True:
                    data = f.read(chunkSize)
                    # print(f"Read data: {data}")
                    if not data:
                        print("No data, breaking")
                        break
                    sock.sendall(data)
                print("File Has Been Sent")
                sock.close()
                null = input("Press Enter To Return To Main Menu")
                mainFunction()
        else:
            sock.close()
            print("Receiver Rejected The Connection")
            null = input("Press ENTER To Return To The Main Menu")
            mainFunction()
    except socket.error:
        sock.close()
        print("There Was An Error Connecting To The Receiver")
        null = input("Press ENTER To Return To The Main Menu")
        mainFunction()



def recieveFileScreen():
    global dencryptionKey
    title()
    print("Waiting For Sender To Connect...")
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    print("Your Ip address: "+ip_address)
    longLine()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', port))
    sock.listen(1)
    client, addr = sock.accept()
    print(str(addr) + " Wants To Send A File...")
    confirm = input("Would You Like To Receive The File? [yes/no]: ")
    longLine()
    if confirm.lower() == "yes":
        client.send(b'1')
        with client, client.makefile('rb') as clientFile:
            print("Getting File Name")
            fileName = clientFile.readline().strip().decode()
            if fileName == '':
                print("File name is empty. Exiting.")
                client.close()
                return
            print("File Name: " + fileName)
            longLine()
            time.sleep(0.3)
            print("Getting File Size")
            length = int(clientFile.readline().strip().decode())
            print("File Size: " + str(length) + " Bytes")
            longLine()
            time.sleep(0.3)
            print("Starting Secure Key Exchange")
            print("Receiving Modulo")
            mod = int(clientFile.readline().strip().decode())
            time.sleep(0.1)
            print("Modulo: " + str(mod))
            print("Receiving Base")
            base = int(clientFile.readline().strip().decode())
            time.sleep(0.1)
            print("Base: " + str(base))
            print("Generating Private Key")
            privateKey = ''.join(str(random.randint(1, 5)) for _ in range(5))
            time.sleep(0.3)
            print("Generating Equation")
            recieverPublicKey = (int(base) ** int(privateKey)) % int(mod)
            time.sleep(0.1)
            print("Sending Public Key")
            client.send((str(recieverPublicKey) + '\n').encode())
            time.sleep(0.1)
            print("Receiving Sender's Public Key")
            senderPublicKey = int(clientFile.readline().strip().decode())
            time.sleep(0.1)
            print("Calculating Key")
            sharedKey = str((senderPublicKey ** int(privateKey)) % int(mod))
            sharedKey = hashlib.sha256(sharedKey.encode()).hexdigest()[:32]
            initVector = b'\x00' * 16
            print("Receiving Encryption Key Size")
            encryptedKeySize = int(clientFile.readline().strip().decode())
            print("Encryption Key Size: " + str(encryptedKeySize) + " Bytes")
            longLine()
            print("Receiving Encrypted Key")
            encryptedKey = clientFile.read(encryptedKeySize)
            decryptor = AES.new(sharedKey.encode('utf-8'), AES.MODE_CBC, initVector)
            decryptedKey = decryptor.decrypt(encryptedKey).strip()
            print("Secure Key Transfer Complete")
            longLine()
            print("Receiving Encrypted File")
            longLine()
            with open(fileName, 'wb') as f:
                remaining = length
                while remaining > 0:
                    print(f"Remaining: {remaining}")
                    chunk = min(remaining, chunkSize)
                    print(f"Chunk Size: {chunk}")
                    data = clientFile.read(chunk)
                    if not data:
                        print("No data received, breaking")
                        break
                    f.write(data)
                    remaining -= len(data)
                    print(f"Received Data: {data}")
            pyAesCrypt.decryptFile(fileName, fileName[:-4], decryptedKey.decode('utf-8'), bufferSize)
            os.remove(fileName)
            print("File Transfer Complete")
            longLine()
            null = input("Press ENTER To Return To The Main Menu")
            mainFunction()
    else:
        client.send(b'0')
        client.close()
        mainFunction()


def encryptScreen():
    title()
    print("Option 1: Encrypt A File")
    longLine()
    fileToEncrypt = input("File To Encrypt: ")
    if len(dencryptionKey) > 0:
        file_name = encrypt_file(fileToEncrypt, dencryptionKey)
    else:
        password = getpass.getpass(prompt='Password: ')
        file_name = encrypt_file(fileToEncrypt, password)
    print(file_name + " Was Successfully Encrypted")
    null = input("Press ENTER To Return To The Main Menu")
    mainFunction()


def decryptScreen():
    title()
    print("Option 2: Decrypt A File")
    longLine()
    fileToDecrypt = input("File To Decrypt: ")
    fileName = fileToDecrypt[:-4]
    if len(dencryptionKey) > 0:
        pyAesCrypt.decryptFile(fileToDecrypt, fileName, dencryptionKey, bufferSize)
        print(fileName + " Was Successfully Decrypted")
    else:
        password = getpass.getpass(prompt='Password: ')
        pyAesCrypt.decryptFile(fileToDecrypt, fileName, password, bufferSize)
        print(fileName + " Was Successfully Decrypted")
    null = input("Press ENTER To Return To The Main Menu")
    mainFunction()

def keyGenScreen(bits):
    title()
    print(f"Option {bits} Bit Key Generation")
    longLine()
    keyName = input("Key File Name: ")
    with open(keyName, 'w') as keyFileObject:
        keyFileObject.write(''.join(random.choice(string.ascii_letters + string.digits) for _ in range(bits)))
    print("Key File Generated Successfully")
    null = input("Press ENTER To Return To The Main Menu")
    mainFunction()

def addKeyScreen():
    title()
    print("Option 10: Add Key File To Session")
    longLine()
    global keyFile
    keyFile = input("Key File Path: ")
    if os.path.exists(keyFile):
        with open(keyFile, 'r') as keyFileObject:
            dencryptionKey = keyFileObject.read()
        print("Key File Added Successfully")
    else:
        print("Invalid Key File Path")
    null = input("Press ENTER To Return To The Main Menu")
    mainFunction()

def removeKeyScreen():
    title()
    print("Option 11: Remove Key From Session")
    longLine()
    global keyFile
    keyFile = ''
    print("Key File Removed Successfully")
    null = input("Press ENTER To Return To The Main Menu")
    mainFunction()

def mainFunction():
    main()

# Run Main Function
mainFunction()