import hashlib
import os
import json
from Crypto.Cipher import AES
from ..utils import fromBase64, toBase64
from ..certmanager import CertManager

def encrypt(pwd, message):
	# Convert message to bytearray
	#message = bytearray(message, 'UTF-8')
	# Generate IV
	iv = os.urandom(AES.block_size)
	# Create Cipher Engine (CBC)
	cipher_engine = AES.new(pwd, AES.MODE_CBC, iv)

	# Divide message in blocks
	parts = [message[i:i + AES.block_size] for i in range(0, len(message), AES.block_size)]
	# Addind IV to beggining of cipher
	ciphertext = iv

	# Encrypt blocks
	for part in parts:
		# Add padding on last block
		if len(part) % AES.block_size != 0:
			ciphertext += cipher_engine.encrypt( pad(part, AES.block_size) )
		else:
			ciphertext += cipher_engine.encrypt( part )

	if len(parts[-1]) % AES.block_size == 0:
		 ciphertext += cipher_engine.encrypt( pad(b'', AES.block_size) )

	# Return Encypted Message
	return ciphertext

def decrypt(pwd, cipher):
	# Divide message in blocks
	parts = [cipher[i:i + AES.block_size] for i in range(0, len(cipher), AES.block_size)]

	# Create Cipher Engine (CBC)
	c = AES.new(pwd, AES.MODE_CBC, parts[0])
	plaintext = b''

	# Decrypt each block starting at the second (first one is IV)
	for part in parts[1:-1]:
		plaintext += c.decrypt(part)

	# Remove padding from last block
	tmp = c.decrypt(parts[-1])
	plaintext += tmp[:-tmp[-1]]

	# Return PlainText
	return plaintext


def pad(data, bLen):
	# Adds padding to block
	return data + bytearray((bLen - len(data) % bLen) * chr(bLen - len(data) % bLen),'UTF-8')


# Helper function to communicate with the servers
# Hybrid approach
def server_encrypt(action, data, cert):
    pwd = os.urandom(32)
    cm = CertManager(cert = cert)
    encrypted_pwd = cm.encrypt(pwd)
    encrypted_data = encrypt(pwd, json.dumps(data).encode('UTF-8'))
    msg = {'ACTION': action, 'EPWD': toBase64(encrypted_pwd), 'DATA':  toBase64(encrypted_data)}
    return msg


def server_decrypt(j, cert, pk):
    cm = CertManager(cert = cert, priv_key = pk)
    pwd = cm.decrypt(fromBase64(j['EPWD']))
    data = decrypt(pwd, fromBase64(j['DATA']))
    return data
