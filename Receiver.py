import socket
from Crypto.PublicKey import RSA
from pyDes import *
import imaplib
import time
import ast

# generate private key
private_key_R = RSA.generate(1024)
# Get the public part
public_key_R = private_key_R.publickey()
# Show the real content of the private part to console, be careful with this!
# print(private_key_R.exportKey())
# Show the real content of the public part to console
# print(public_key_R.exportKey())

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)
mail = imaplib.IMAP4_SSL('imap.gmail.com')
# imaplib module implements connection based on IMAPv4 protocol
My_Email = input("Your Email : ")
My_Pass = input("Your Password : ")
mail.login(My_Email , My_Pass)
Sender_email = input("Sender Email : ")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        #print('Connected by', addr)
        while True:
            # sender is connected
            data = conn.recv(1024)
            est_con = data.decode()
            #print(est_con)
            if not data:
                break
             # send public key
            conn.send(private_key_R.exportKey())#done
# receive cipher
time.sleep(10)
stat , content = mail.select('Inbox', '(FROM {0})'.format(Sender_email.strip()))
stat , data = mail.fetch(content[0],'(UID BODY[TEXT])')
v = data[0][1].decode()
ciphertext = v.split('\n')
#print("i got cipher", ciphertext[0])
#print('i got encrypted session key', ciphertext[1])
enc_Ks = ast.literal_eval(ciphertext[1])
Ks= private_key_R.decrypt(enc_Ks)
#print('Session Key',Ks.decode())
#decrypt cipher with decrpyted key
d = des(Ks)
plain = d.decrypt(ast.literal_eval(ciphertext[0]) , padmode=PAD_PKCS5 )
print("this is the email: ",plain.decode())
