from des import DesKey
from random import randint
from time import time
import matplotlib.pyplot as plt


def brute_force_des(key_size):
    # Generating random key of 'key_size' bits in bytes format
    key = randint(2 ** (key_size - 1), 2 ** key_size - 1).to_bytes(8, byteorder='big')
    des = DesKey(key)
    # Chosen text pair
    plain_text = b"Hello World!"
    cypher_text = des.encrypt(plain_text, padding=True)
    # Redundant Check
    # deciphered_text = des.decrypt(cypher_text, padding=True)

    # Calculating Time of brute-force attack
    start = time()
    # Iterating on all possible space of keys
    for i in range(2 ** key_size):
        des = DesKey(i.to_bytes(8, byteorder='big'))
        decrypted_text = des.decrypt(cypher_text, padding=True)
        if decrypted_text == plain_text:
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
