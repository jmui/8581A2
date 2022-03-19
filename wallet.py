#!/usr/bin/python3

#FSCT 8561
#A2
#wallet.py


#need to install the pycryptodome library
#pip install pycryptodome

import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad




def tokenGenerator(senderWID, receiverWID, amount, counter):
	token = ""


	return token


#withdraw money from bank
#emd input must be in JSON format string
def bankWithdrawl(kWallet):
	value = 0
	emd = input("Enter Electronic Money Draft token: ")

	try:
		encryptedJSON = json.loads(emd)
		iv = b64decode(encryptedJSON['iv'])
		ciphertext = b64decode(encryptedJSON['ct'])
		cipher = AES.new(kWallet.digest(), AES.MODE_CBC, iv)
		plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
		value = int(plaintext.hex(), 16)
		print("Withdrawing: $" + str(value))
	except (ValueError, KeyError):
		print("Decryption failed. Could not withdraw from bank")
	return value



def sendMoney(amount, balance):



	return balance




option = 9
balance = 0
#list of synchronized wallets
walletList = []
sIDInput = input("Enter 8 digit ID: ")
#student ID in byte format
sID = str.encode(sIDInput)

#last 4 characters of student ID will be the wallet ID
wID = sIDInput[-4:]

#wallet's key. SHA-256 hash of the student number. 32 bits
kWallet = SHA256.new(sID)
#print("Wallet secret key: " + kWallet.hexdigest())

#bank's secret key. taken from assignment instructions
kBank = "F25D58A0E3E4436EC646B58B1C194C6B505AB1CB6B9DE66C894599222F07B893"




#main menu loop
while option != 0:
	print("\n------------------------------")
	print("1: Withdraw from bank\n2: Synchronize wallets\n3: Send money\n4: Receive money\n5: Print balance\n6: Exit")
	print("------------------------------")
	option = input("Select an option: ")
	print("\n")
	if option == "1":
		balance = balance + bankWithdrawl(kWallet)
		print("Balance: $" + str(balance))
	elif option == "2":
		print("222")
	elif option == "3":
		print("333")
		sendAmount = input("Enter amount to send: ")
		balance = sendMoney(sendAmount, balance)
	elif option == "4":
		print("444")
	elif option == "5":
		print("Balance: $" + str(balance))
	elif option == "6":
		option = 0
		print("Exiting\n")
	else:
		print("Invalid input\n")


