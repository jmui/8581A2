#!/usr/bin/python3

#FSCT 8561
#A2
#bank.py


#need to install pycryptodome library
#pip install pycryptodome

import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256



def createTransaction(amount):
	transaction = ""



	return transaction



option = 9
bID = b'1234567890'
bKey = SHA256.new(bID)
print(bKey.digest())



while option != 0:
	print("1: Send to wallet\n2: Exit")
	option = input("Pick an option: ")

	if option == "1":
		print("111")
	elif option == "2":
		option = 0
		print("Exiting")
	else:
		print("Invalid input\n")


