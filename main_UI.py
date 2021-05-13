from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import binascii

from tkinter import *
from tkinter import filedialog


def encrypt_AES_GCM(msg, password, aad):
    salt = get_random_bytes(16)
    secretKey = PBKDF2(password, salt, 32, count=1000000)

    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    aesCipher.update(aad)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (aad, salt, ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(encryptedMsg, password):
    (aad, salt, ciphertext, nonce, authTag) = encryptedMsg
    secretKey = PBKDF2(password, salt, 32, count=1000000)
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    aesCipher.update(aad)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def encrypt_file(file_name, key, aad):
    key = key.encode("utf8")
    aad = aad.encode("utf8")
    with open(file_name, 'rb') as fo:
        plaintext = fo.read()
    enc = encrypt_AES_GCM(plaintext, key, aad)
    aad = binascii.hexlify(enc[0])
    salt = binascii.hexlify(enc[1])
    ciphertext = binascii.hexlify(enc[2])
    aesIV = binascii.hexlify(enc[3])
    authTag = binascii.hexlify(enc[4])
    #print(str(salt))
    #print(salt)
    save_srting = str(aad) + "," + str(salt) + "," + str(ciphertext) + "," + str(aesIV) + "," + str(authTag)
    with open(file_name + ".enc", 'w') as fo:
        fo.write(save_srting)

def decrypt_file(file_name, key):
    key = key.encode("utf8")
    enc_file = file_name + ".enc"
    with open(enc_file, 'r') as fo:
        ciphertext = fo.read()
        ciphertext = ciphertext.split(",")
    bytes_ciphertext = []
    for s in ciphertext:
        s = s[2:]
        s = s[:-1]
        bytes_ciphertext.append(bytes.fromhex(s))
    dec = decrypt_AES_GCM(bytes_ciphertext, key)
    with open(file_name, 'wb') as fo:
        fo.write(dec)    

def encrypt_msg(plaintext, key, aad):
    #print(aad)
    aad = aad.encode("utf8")
    #print(aad)
    key = key.encode("utf8")
    #print(key)
    plaintext = plaintext.encode("utf8")
    #print(plaintext)
    enc = encrypt_AES_GCM(plaintext, key, aad)
    aad = binascii.hexlify(enc[0])
    salt = binascii.hexlify(enc[1])
    ciphertext = binascii.hexlify(enc[2])
    aesIV = binascii.hexlify(enc[3])
    authTag = binascii.hexlify(enc[4])
    #print(str(salt))
    #print(salt)
    save_srting = str(aad) + "," + str(salt) + "," + str(ciphertext) + "," + str(aesIV) + "," + str(authTag)
    with open("text_cipher.txt.enc", 'w') as fo:
        fo.write(save_srting)

def decrypt_msg(key):
    key = key.encode("utf8")
    with open("text_cipher.txt.enc", 'r') as fo:
        ciphertext = fo.read()
        ciphertext = ciphertext.split(",")
    bytes_ciphertext = []
    for s in ciphertext:
        s = s[2:]
        s = s[:-1]
        bytes_ciphertext.append(bytes.fromhex(s))
    #print(bytes_ciphertext)
    dec = decrypt_AES_GCM(bytes_ciphertext, key)
    with open("text_decrypt.txt", 'w') as fo:
        fo.write(dec.decode("utf-8"))  

def browseFiles():
    filename = filedialog.askopenfilename(initialdir = "/",title = "Select a File",filetypes = (("Text files","*.txt*"),("all files","*.*")))
    label_file_add.configure(text=filename)

def pass_btn():
    label_Password.configure(text= 'Password : ' + Password.get())  
        
def aad_btn():
    label_aad.configure(text= 'AAD : ' + aad.get())  
        

def enc_btn_file():
    input_file = label_file_add.cget("text")
    encrypt_file(input_file, Password.get(), aad.get())

def dec_btn_file():
    input_file = label_file_add.cget("text")
    decrypt_file(input_file, Password.get())    

def enc_btn_text():
    ptext = text_box.get("1.0",'end-1c')
    encrypt_msg(ptext, Password.get(), aad.get())

def dec_btn_text():
    decrypt_msg(Password.get())    
	
																								
window = Tk()
window.title('AES GCM')
window.minsize(350,400)
window.config(background = "white")



# UI elements
Password = StringVar()
label_Password = Label(window,text = "Password ",width = 50, height = 2,fg = "blue") 
passEntered = Entry(window, width = 25, textvariable = Password)
button_getpass = Button(window,text = "Enter Pass",command = pass_btn)

aad = StringVar()
label_aad = Label(window,text = "AAD ",width = 50, height = 2,fg = "blue") 
aadEntered = Entry(window, width = 25, textvariable = aad)
button_getaad = Button(window,text = "Enter Pass",command = aad_btn)

input_file = StringVar()	
label_file = Label(window,text = "File Encrypt ",width = 50, height = 4,fg = "blue")
label_file_explorer = Label(window,text = "File Explorer ",width = 50)
label_file_add = Label(window,text = "...",width = 50)
button_explore = Button(window,text = "Browse Files",command = browseFiles)
button_encrypt_File = Button(window, text = "Encrypt File", command = enc_btn_file)        
button_decrypt_File = Button(window, text = "Decrypt File", command = dec_btn_file)         



text_message = StringVar()
label_Text = Label(window,text = "Text Encrypt ",width = 50, height = 4,fg = "blue")
text_box = Text(window, width = 25, height = 5)
button_encrypt_text = Button(window, text = "Encrypt Mess", command = enc_btn_text)     
button_decrypt_text = Button(window, text = "Decrypt Mess", command = dec_btn_text)    


# placing
label_Password.grid(column = 0, row = 1)
passEntered.grid(column = 0, row = 2)
button_getpass.grid(column = 0, row = 3)

label_aad.grid(column = 0, row = 4)
aadEntered.grid(column = 0, row = 5)
button_getaad.grid(column = 0, row = 6)

label_file.grid(column = 0, row = 7)
label_file_explorer.grid(column = 0, row = 8)
label_file_add.grid(column = 0, row = 9)

button_explore.grid(column = 0, row = 10)
button_encrypt_File.grid(column = 0,row = 11)
button_decrypt_File.grid(column = 0,row = 12)

label_Text.grid(column = 0, row = 13)
text_box.grid(column = 0,row = 14)
button_encrypt_text.grid(column = 0,row = 15)
button_decrypt_text.grid(column = 0,row = 16)





window.mainloop()
