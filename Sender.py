import random
import smtplib
import socket
import ssl
from email.message import EmailMessage
from Crypto.PublicKey import RSA
from numpy import long
from pyDes import *
from time import time
import matplotlib.pyplot as plt
from des import DesKey

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server
msg ='Hello Bob'
port1 = 465  # For SSL
sender_email = input("Your Email : ")
password = input("Enter Your Password : ")
receiver_email = input("Receiver Email : ")
Subject = input( "Email Subject : ")
email = input("Your Message :")

def generate_Ks (key_size):
    Ks = long(random.getrandbits(key_size))
    r = range((2**(key_size-1))+1, ((2**(key_size))-1))
    while( Ks not in r ):
        Ks = long(random.getrandbits(key_size))

    return Ks

def send_mail(initial_array):
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", port1, context=context) as server:
        server.login(sender_email, password)
        msg = EmailMessage()
        msg.set_content(initial_array)
        msg['Subject'] = Subject
        msg['From'] = sender_email
        msg['To'] = receiver_email
        server.sendmail(sender_email, receiver_email, msg.as_bytes())



with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    #send connection msg
    s.send(msg.encode())
    #receive public key of bob
    myobj = s.recv( 1024 )
    #print('object y rb ', myobj)
    bob_key = RSA.importKey(myobj)
    #print('RSA OB ' , bob_key)
    #print("pub of bob not exported ",bob_key.publickey())
    #print(" bob's public key ",bob_key.publickey().exportKey()) #done

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


def brute_force_des(key_size):

    # Calculating Time of brute-force attack
    start = time()
    # Iterating on all possible space of keys
    for i in range(2 ** key_size):
        des = DesKey(i.to_bytes(8, byteorder='big'))
        decrypted_text = des.decrypt(ciphertext, padding=True)
        if decrypted_text == email:
            # print(i.to_bytes(8, byteorder='big'), decrypted_text, sep = '\n', end = '\n\n')
            # print(key, des, plain_text, cypher_text, deciphered_text, des.is_single(), sep='\n', end = '\n\n')
            return time() - start

def graph_time_vs_key(min_key=8, max_key=56):
    # Generate graph of time taken to break a key of specific size between min & max
    breaking_times = []
    for i in range(min_key, max_key + 1):
        breaking_times.append(brute_force_des(i))
        print(i)
        plt.plot(range(min_key, i + 1), breaking_times)
        plt.xlabel('Key Size (Bits)')
        plt.ylabel('Time (Seconds)')
        plt.title('DES Brute-force Attack (' + str(i) + ')')
        plt.show()


graph_time_vs_key()
