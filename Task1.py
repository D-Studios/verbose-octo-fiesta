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

LAST_BYTE = -1
MINIMUM_PAD_SIZE = 1
LAST_INDEX = -1
SECOND_LAST_BYTE = -2
WRONG_PADDING_NUMBER = 255
BLOCKSIZE = 16

q = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
a = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
ya = 0
yb = 0
c0 = ""
c1 = ""
random.seed(42)
iv = 0


USER_STRING = ""

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

def custom_url_encode(string, encode_chars):
	encode_set = set(encode_chars)
	encoded_string = ''
	for char in string:
		if char in encode_set:
			encoded_string += urllib.parse.quote(char)
		else:
			encoded_string += char 
	return encoded_string 

def custom_url_decode(encoded_string, decode_chars):
	decode_set = set(decode_chars)
	decoded_string = ''
	i=0
	while i<len(encoded_string):
		char = encoded_string[i]
		if char == '%':
			if i+2 < len(encoded_string):
				hex_value = encoded_string[i+1:i+3]
				try:
					decoded_char = chr(int(hex_value, 16))
					if decoded_char in decode_set:
						decoded_string += decoded_char
						i+=3
						continue
				except ValueError:
					pass
		decoded_string += char
		i+=1
	return decoded_string

def verify(string, key, iv):
	decryptedBytes = cbc_decrypt(string, key, iv)
	print("Decrypted Bytes : ", decryptedBytes)
	if b';admin=true;' in decryptedBytes:
		return True
	else:
		return False

	
def submit(key, iv):
	#Type 'abcdefghijkl;admin=true;' 
	global USER_STRING
	user_provided_string = input("Enter arbitrary string : ")
	plaintext = "userid=456;userdata=" 
	plaintext += custom_url_encode(user_provided_string, [';', '=']) 
	plaintext += ";session-id=31337"
	#userid=456;userdata=abcdefghijkl;admin=true;session-id=31337
	encodedPlainText = plaintext.encode('utf-8')
	USER_STRING = encodedPlainText
	ciphertext = cbc_encrypt(encodedPlainText, key, iv)
	checker = cbc_decrypt(ciphertext, key, iv)
	if(checker != encodedPlainText):
		raise ValueError('CBC Encryption Failed')
	return ciphertext

def visualize_blocks(plaintext):
    """Visualize how the plaintext splits into 16-byte blocks."""
    blocks = split_blocks(plaintext)
    for i, block in enumerate(blocks):
        print(f"Block {i + 1}: {block} ({block.decode(errors='replace')})")

def split_blocks(data):
    """Split the given data into blocks of size BLOCKSIZE (16 bytes)."""
    return [data[i:i + BLOCKSIZE] for i in range(0, len(data), BLOCKSIZE)]

def flip_bit(ciphertext, block_idx, byte_offset, bit_index):
    # Convert ciphertext to a mutable bytearray
    mutable_ciphertext = bytearray(ciphertext)

    # Get the position in the ciphertext we want to flip
    position = block_idx * BLOCKSIZE + byte_offset

    # Flip the specified bit
    mutable_ciphertext[position] ^= (1 << bit_index)

    return bytes(mutable_ciphertext)

def bob(q, a):
	global ya, yb, c0, c1, iv
	xb = random.randint(1, q-1)
	yb = pow(a, xb, q)
	s = pow(ya, xb, q)
	hash_object = hashlib.sha256()
	hash_object.update(str(s).encode('utf-8'))
	# print(type(hash_object.digest()))
	k = hash_object.digest()[:16]
	# print(type(k))
	m1 = "Hi Alice!".encode('utf-8')
	c1 = cbc_encrypt(m1, k, iv)
	print("Decrypted c1: ", cbc_decrypt(c1, k, iv))

def alice (q, a) :
	global ya, yb, c0, c1, iv
	xa = random.randint(1, q-1)
	ya = pow(a, xa, q)
	bob (q, a)
	s = pow(yb, xa, q)
	hash_object = hashlib.sha256()
	hash_object.update(str(s).encode('utf-8'))
	k = hash_object.digest()[:16]
	m0 = "Hi Bob!".encode('utf-8')
	c0 = cbc_encrypt(m0, k, iv)
	print("Decrypted c0: ", cbc_decrypt(c0, k, iv))

def main():
	global q, a, ya, yb, c0, c1, iv
	iv = generate_random_iv(16)
	alice(q, a)
	print("C0 : " , c0)
	print("C1 : " , c1)

main()