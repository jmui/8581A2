#!/usr/bin/python3

#FSCT 8561
#A2
#bank.py


#need to install pycryptodome library
#pip install pycryptodome

import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


option = 9
#this value is from the assignment instructions
kBank = "F25D58A0E3E4436EC646B58B1C194C6B505AB1CB6B9DE66C894599222F07B893"



def createTransaction(amount):

	amount = int(amount)
	#used for calculating KWallet using SHA-25
	#sIDInput = input("Enter 8 digit ID: ")
	sIDInput = "01237158"
	sID = str.encode(sIDInput)
	kWallet = SHA256.new(sID)
	#print(kWallet.hexdigest())
	wID = sIDInput[-4:]

	#convert amount to hex value, thne remove 0x from string
	hexAmount = hex(amount)
	hexAmount = hexAmount[2:]

	#pad hexAmount to 32 characters using 0s
	numZeroes = 32 - len(hexAmount)
	zeroes = ""
	if numZeroes > 0:
		for i in range(numZeroes):
			zeroes = zeroes + "0"
		hexAmount = zeroes + hexAmount


	#create Electronic Money Draft
	cipher = AES.new(kWallet.digest(), AES.MODE_GCM)
	cipherText, tag = cipher.encrypt_and_digest(hexAmount)


while option != 0:
	print("\n1: Send to wallet\n2: Exit")
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


