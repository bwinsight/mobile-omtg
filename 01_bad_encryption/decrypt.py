import base64

base64password = 'vJqfip28ioydips='
encoded = bytearray(base64.b64decode(base64password))
for i in range(len(encoded)):
	encoded[i] = (encoded[i] ^ -1) & 255
	encoded[i] = encoded[i] ^ 16

print(encoded.decode())
