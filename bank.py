#!/usr/bin/python3

#FSCT 8561
#A2
#bank.py


#requires pycryptodome library
#pip install pycryptodome

import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad


option = 9


def createTransaction(amount):

	amount = int(amount)
	#used for calculating KWallet using SHA-25
	sIDInput = input("Enter 8 digit wallet ID: ")
	sID = str.encode(sIDInput)
	kWallet = SHA256.new(sID)
	wID = sIDInput[-4:]

	#convert amount to hex value, the remove 0x from string
	hexAmount = hex(amount)
	hexAmount = hexAmount[2:]

	#pad hexAmount to 32 characters using 0s
	numZeroes = 32 - len(hexAmount)
	zeroes = ""
	if numZeroes > 0 and numZeroes < 32:
		for i in range(numZeroes):
			zeroes = zeroes + "0"
		hexAmount = zeroes + hexAmount


	#create Electronic Money Draft string to be used in wallet
	#copy generated JSON string to the wallet to withdraw money
	hexAmountBytes = bytes.fromhex(hexAmount)
	cipher = AES.new(kWallet.digest(), AES.MODE_CBC)
	ciphertextBytes = cipher.encrypt(pad(hexAmountBytes, AES.block_size))
	iv = b64encode(cipher.iv).decode('utf-8')
	ciphertext = b64encode(ciphertextBytes).decode('utf-8')
	emd = json.dumps({'iv':iv, 'ct':ciphertext})
	print("\nSending: $" + str(amount) + "\nTo wallet #: " + wID)
	print("Token:")
	print(emd)




while option != 0:
	print("\n---------------------------------")
	print("1: Withdraw to wallet\n2: Exit")
	print("---------------------------------")
	option = input("Pick an option: ")

	if option == "1":
		amount = input("Enter an amount: ")
		if amount.isnumeric():
			createTransaction(amount)
		else:
			print("String is not numeric\n")
	elif option == "2":
		option = 0
		print("Exiting")
	else:
		print("Invalid input\n")


