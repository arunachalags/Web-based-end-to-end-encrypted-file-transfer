import os
import random
import string
import time
import socket
import hashlib
import pyfiglet
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from Crypto.Cipher import AES
import pyAesCrypt

# Global Variables Initialization
keyFile = ''  # Key File
dencryptionKey = ''  # Key File Contents
bufferSize = 128 * 1024
chunkSize = 16
port = 7777

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def longLine():
    print("--------------------------------------------------------------------------------")

def title():
    clear()
    ascii_banner = pyfiglet.figlet_format("End To End Encrypted File Transfer")
    print(ascii_banner)
    longLine()

def updateKeyFileLabel():
    if keyFile:
        keyFileLabel.config(text=f"Key File: {keyFile}")
    else:
        keyFileLabel.config(text="No Key File Loaded")

def browseKeyFile():
    global keyFile, dencryptionKey
    keyFile = filedialog.askopenfilename()
    if keyFile:
        with open(keyFile, 'r') as keyFileObject:
            dencryptionKey = keyFileObject.read()
        messagebox.showinfo("Key File", "Key File Added Successfully")
    updateKeyFileLabel()

def removeKeyFile():
    global keyFile, dencryptionKey
    keyFile = ''
    dencryptionKey = ''
    messagebox.showinfo("Key File", "Key File Removed Successfully")
    updateKeyFileLabel()

def encryptFile():
    fileToEncrypt = filedialog.askopenfilename()
    if fileToEncrypt:
        fileName = fileToEncrypt + ".dnc"
        if dencryptionKey:
            pyAesCrypt.encryptFile(fileToEncrypt, fileName, dencryptionKey, bufferSize)
        else:
            password = simpledialog.askstring("Password", "Enter password:", show='*')
            pyAesCrypt.encryptFile(fileToEncrypt, fileName, password, bufferSize)
        messagebox.showinfo("Encryption", f"{fileName} Was Successfully Encrypted")

def decryptFile():
    fileToDecrypt = filedialog.askopenfilename()
    if fileToDecrypt:
        fileName = fileToDecrypt[:-4]
        if dencryptionKey:
            pyAesCrypt.decryptFile(fileToDecrypt, fileName, dencryptionKey, bufferSize)
        else:
            password = simpledialog.askstring("Password", "Enter password:", show='*')
            pyAesCrypt.decryptFile(fileToDecrypt, fileName, password, bufferSize)
        messagebox.showinfo("Decryption", f"{fileName} Was Successfully Decrypted")

def generateKey(bits):
    keyName = simpledialog.askstring("Key File", "Enter Key File Name:")
    if keyName:
        with open(keyName, 'w') as keyFileObject:
            keyFileObject.write(''.join(random.choice(string.ascii_letters + string.digits) for _ in range(bits)))
        messagebox.showinfo("Key Generation", f"{keyName} Was Successfully Generated")

def sendFileScreen():
    rHost = simpledialog.askstring("Receiver's IP", "Enter Receiver's IP:")
    if not rHost:
        messagebox.showerror("Error", "Receiver's IP is required")
        return

    fileToSend = filedialog.askopenfilename()
    if not fileToSend:
        messagebox.showerror("Error", "File to send is required")
        return

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
                    if not data:
                        break
                    sock.sendall(data)
                print("File Has Been Sent")
                sock.close()
                messagebox.showinfo("Success", "File sent successfully")
        else:
            sock.close()
            print("Receiver Rejected The Connection")
            messagebox.showerror("Error", "Receiver Rejected The Connection")
    except socket.error:
        sock.close()
        print("There Was An Error Connecting To The Receiver")
        messagebox.showerror("Error", "There Was An Error Connecting To The Receiver")

def recieveFileScreen():
    global dencryptionKey
    title()
    print("Waiting For Sender To Connect...")
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    print("Your IP address: " + ip_address)
    longLine()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', port))
    sock.listen(1)
    client, addr = sock.accept()
    print(str(addr) + " Wants To Send A File...")
    confirm = simpledialog.askstring("Confirmation", "Would You Like To Receive The File? [yes/no]: ")
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
            senderPublicKey = clientFile.readline().strip().decode()
            time.sleep(0.1)
            print("Calculating Key")
            sharedKey = str((int(senderPublicKey) ** int(privateKey)) % int(mod))
            sharedKey = hashlib.sha256(sharedKey.encode()).hexdigest()[:32]
            initVector = '\x00' * 16
            print("Receiving Encryption Key Size")
            encryptedKeySize = int(clientFile.readline().strip().decode())
            print("Encryption Key Size: " + str(encryptedKeySize) + " Bytes")
            longLine()
            print("Receiving Encrypted Key")
            encryptedKey = clientFile.read(encryptedKeySize)
            decryptor = AES.new(sharedKey.encode('utf-8'), AES.MODE_CBC, initVector.encode('utf-8'))
            decryptedKey = decryptor.decrypt(encryptedKey).strip()
            dencryptionKey = decryptedKey.decode('utf-8')
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
            pyAesCrypt.decryptFile(fileName, fileName[:-4], dencryptionKey, bufferSize)
            os.remove(fileName)
            print("File Transfer Complete")
            longLine()
            messagebox.showinfo("Success", "File received successfully")
    else:
        client.send(b'0')
        client.close()

root = tk.Tk()
root.title("Encryption and Decryption Software")
root.config(bg="white")
tk.Label(root, text="End To End Encrypted File Transfer", font=("Comic Sans MS", 20),fg="black",bg="white").pack(pady=10)

frame = tk.Frame(root)
frame.pack(pady=20)

tk.Button(frame, text="Encrypt A File", command=encryptFile,bg="#39ff14", width=30).grid(row=0, column=0, padx=5, pady=6)
tk.Button(frame, text="Decrypt A File", command=decryptFile,bg="#39ff14", width=30).grid(row=0, column=1, padx=5, pady=6)
tk.Button(frame, text="Send A Secure File", command=sendFileScreen,bg="#39ff14", width=30).grid(row=1, column=0, padx=5, pady=6)
tk.Button(frame, text="Receive A Secure File", command=recieveFileScreen, bg="#39ff14",width=30).grid(row=1, column=1, padx=5, pady=6)
tk.Button(frame, text="Generate 16 Bit Key", command=lambda: generateKey(16),bg="#39ff14", width=30).grid(row=2, column=0, padx=5, pady=6)
tk.Button(frame, text="Generate 64 Bit Key", command=lambda: generateKey(64),bg="#39ff14", width=30).grid(row=2, column=1, padx=5, pady=6)
tk.Button(frame, text="Generate 128 Bit Key", command=lambda: generateKey(128), bg="#39ff14",width=30).grid(row=3, column=0, padx=5, pady=6)
tk.Button(frame, text="Add Key File To Session", command=browseKeyFile,bg="#39ff14", width=30).grid(row=3, column=1, padx=5, pady=6)
tk.Button(frame, text="Remove Key From Session", command=removeKeyFile,bg="#39ff14", width=30).grid(row=4, column=0, padx=5, pady=6)
tk.Button(frame, text="Exit", command=root.quit,bg="#39ff14", width=30).grid(row=4, column=1, padx=5, pady=6)

keyFileLabel = tk.Label(root, text="No Key File Loaded", font=("Arial", 12),bg="white")
keyFileLabel.pack(pady=20)

updateKeyFileLabel()
root.mainloop()