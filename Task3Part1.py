import random
import hashlib
from Crypto.Cipher import AES
import base64
import random
import string
import urllib.parse
from Crypto.Cipher import AES
import math
from Crypto.Util.Padding import pad,unpad
import os
from sympy import isprime, mod_inverse
import sympy

LAST_BYTE = -1
MINIMUM_PAD_SIZE = 1
LAST_INDEX = -1
SECOND_LAST_BYTE = -2
WRONG_PADDING_NUMBER = 255
BLOCKSIZE = 16

C = 0
publicKey = [0, 0]
privateKey = [0,0]


def xorFunction(input_bytes, key_bytes):
    j=0 
    last_index = len(key_bytes)-1
    bytes_list = []
    for i in range(0, len(input_bytes)):
        if j>last_index:
            j=0
        bytes_list.append(input_bytes[i] ^ key_bytes[j])
        j+=1
    result_bytes = bytes_list
    return result_bytes

def pad(plaintextMessage):
	padSize = BLOCKSIZE - (len(plaintextMessage) % BLOCKSIZE)
	padding = bytes([padSize] * padSize)
	data = plaintextMessage + padding 
	return data

def unpad(data):
	data_length = len(data)
	last_data_index = data_length + LAST_INDEX
	pad_index = last_data_index
	padSize = data[LAST_BYTE]
	if data_length%BLOCKSIZE != 0:
		raise ValueError("Pad size is not multiple of blocksize.")
	if padSize < MINIMUM_PAD_SIZE or padSize > data_length:
		raise ValueError("Invalid padding size")
	i = 0
	while True:
		if i>=padSize:
			break
		pad_byte = data[pad_index]
		if pad_byte != padSize:
			raise ValueError("Invalid padding byte")
		i+=1
		pad_index-=1
	return data[0:data_length-padSize]

def cbc_encrypt(plaintext, key, initializationVector):
    data = pad(plaintext)
    # print(" Key : " , type(key))
    # print(" initializationVector : " , type(initializationVector))
    cipher = AES.new(key, AES.MODE_CBC, initializationVector)
    ciphertext = cipher.encrypt(data)
    return ciphertext

def cbc_decrypt(ciphertext, key, initializationVector):
    cipher = AES.new(key, AES.MODE_CBC, initializationVector)
    decryptedCipherText = cipher.decrypt(ciphertext)
    plaintext = unpad(decryptedCipherText)
    return plaintext


def generate_random_key(length) :
	characters = string.ascii_letters + string.digits
	random_key = ''.join(random.choice(characters) for i in range(length))
	return random_key.encode('utf-8')

def generate_random_iv(length):
	random_iv = bytes(random.getrandbits(8) for i in range(length))
	return random_iv

def numberToHexToString(num):
	hex_string = hex(num)[2:]
	if len(hex_string) % 2 != 0:
		hex_string = '0' + hex_string
	byte_array = bytes.fromhex(hex_string)
	result_string = byte_array.decode('utf-8')
	return result_string

def RSA_Decryption() :
	global C, privateKey
	M = pow(C, privateKey[0], privateKey[1])
	print("Decryption : ", numberToHexToString(M))

def RSA_Encryption(M) : 
	global C, publicKey
	C = pow(M, publicKey[0], publicKey[1])
	print("Encryption : " , C)


def RSA_Setup():
	global publicKey, privateKey
	p = sympy.randprime(pow(2,2047), pow(2, 2048))
	q = sympy.randprime(pow(2,2047), pow(2,2048))
	n = p * q	
	eulerTotientFunction = (p-1) * (q-1)
	e = 65537
	d = mod_inverse(e, eulerTotientFunction)
	publicKey = [e, n]
	privateKey = [d, n]

def main():
	plaintext = input("Enter plaintext : ")
	M = int(plaintext.encode('utf-8').hex(), 16)
	RSA_Setup()
	RSA_Encryption(M)
	RSA_Decryption()

main()