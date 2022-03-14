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
bKey = "F25D58A0E3E4436EC646B58B1C194C6B505AB1CB6B9DE66C894599222F07B893"




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


