#!/usr/bin/python3

#FSCT 8561
#A2
#wallet.py


#need to install pycryptodome library
#pip install pycryptodome

import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes



option = 9
balance = 0
#list of wallets
walletList = []
#sIDInput = input("Enter student ID: ")
sIDInput = "01237158"
#student ID in byte format
sID = str.encode(sIDInput)

#last 4 characters of student ID will be the wallet ID
wID = sIDInput[-4:]

#wallet's key. SHA-256 hash of the student number. 32 bits
wKey = SHA256.new(sID)
print(wKey.hexdigest())

#bank's secret key. taken from assignment instructions
bKey = "F25D58A0E3E4436EC646B58B1C194C6B505AB1CB6B9DE66C894599222F07B893"


#wallet's secret key generated using AES-256
wCipher = AES.new(wKey.digest(), AES.MODE_GCM)
nonce = wCipher.nonce
print(nonce)
nonceStr = base64.b64encode(nonce).decode('utf-8')
print("Nonce: " + nonceStr)
aaa = base64.b64decode(nonceStr)
print(aaa)


def bankWithdrawl(withdrawlAmount):
	value = 0


	return value



def sendMoney(amount, balance):



	return balance



while option != 0:
	print("1: Withdraw from bank\n2: Synchronize wallets\n3: Send money\n4: Receive money\n5: Print balance\n6: Exit")
	option = input("Select an option: ")
	if option == "1":
		print("111")
		withdrawlAmount = input("Enter withdraw amount: ")
		balance = balance + bankWithdrawl(withdrawlAmount)
	elif option == "2":
		print("222")
	elif option == "3":
		print("333")
		sendAmount = input("Enter amount to send: ")
		balance = sendMoney(sendAmount, balance)
	elif option == "4":
		print("444")
	elif option == "5":
		print("Balance = " + str(balance) + "\n")
	elif option == "6":
		option = 0
		print("Exiting\n")
	else:
		print("Invalid input\n")


