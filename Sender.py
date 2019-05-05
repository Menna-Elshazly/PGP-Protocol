import random
import smtplib
import socket
import ssl
from email.message import EmailMessage
from Crypto.PublicKey import RSA
from numpy import long
from pyDes import *

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server
msg ='Hello Bob'
port1 = 465  # For SSL
sender_email = input("Your Email : ")
password = input("Enter Your Password : ")
receiver_email = input("Receiver Email : ")
email = input("Your Message :")


def generate_Ks (bit_length):
    Ks = long(random.getrandbits(bit_length))
    r = range((2**(bit_length-1))+1, ((2**(bit_length))-1))
    while(Ks not in r):
        Ks = long(random.getrandbits(bit_length))

    return Ks

def send_mail(initial_array):
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", port1, context=context) as server:
        server.login(sender_email, password)
        msg = EmailMessage()
        msg.set_content(initial_array)
        msg['Subject'] = 'wave'
        msg['From'] = sender_email
        msg['To'] = receiver_email
        server.sendmail(sender_email, receiver_email, msg.as_bytes())



with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    #send connection msg
    s.send(msg.encode())
    #receive public key of bob
    myobj = s.recv( 1024 )
    bob_key = RSA.importKey(myobj)


#generate session key
Ks = str( generate_Ks(32))[:-2]
#print('random session key ', Ks)
#encrypt session key using  RSA
encrypted_ks = bob_key.encrypt(Ks.encode(), None)
#print('encrypted session key ', encrypted_ks[0])
#encrypt mail with session key using DES
d = des(Ks)
ciphertext= d.encrypt(email ,padmode=PAD_PKCS5 )
#print("i'm sending cipher ", ciphertext)
#send cipher & encrypted session key by email
send_mail(str(ciphertext)+'\n'+str(encrypted_ks))



