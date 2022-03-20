#!/usr/bin/python3

#FSCT 8561
#A2
#wallet.py


#requires pycryptodome library
#pip install pycryptodome

import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad



#encrypted a string in JSON format
#outputs encrypted JSON token
#does not return anything
def encryption(inputString, key):
	byteString = bytes.fromhex(inputString)
	cipher = AES.new(key.digest(), AES.MODE_CBC)
	ciphertextBytes = cipher.encrypt(pad(byteString, AES.block_size))
	iv = b64encode(cipher.iv).decode('utf-8')
	ciphertext = b64encode(ciphertextBytes).decode('utf-8')
	output = json.dumps({'iv':iv, 'ct':ciphertext})
	print("Token:")
	print(output)
	print("\n")



#decrypt a string in JSON format
#returns plaintext string
def decryption(inputString, key):
	try:
		encryptedJSON = json.loads(inputString)
		iv = b64decode(encryptedJSON['iv'])
		ciphertext = b64decode(encryptedJSON['ct'])
		cipher = AES.new(key.digest(), AES.MODE_CBC, iv)
		plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
	except (ValueError, KeyError):
		print("Decryption failed. Could not withdraw from bank")

	return plaintext



#pad string with zeroes
#returns a string
def padZeroes(inputString, count):

	numZeroes = count - len(inputString)
	zeroes = ""
	if numZeroes > 0 and numZeroes < count:
		for i in range(numZeroes):
			zeroes = zeroes + "0"
		inputString = zeroes + inputString

	return inputString



#increment counter
#input is hex string
#returns hex string
def incrementCounter(counter):

	counter = hex(int(counter, 16) + int(1, 16))

	return counter



#generate token for synchronizing wallets and sending money
#all arguments must be strings
#returns a string in hex format
def generateToken(wID, wIDB, amount, counter):
	token = ""

	#convert wallet IDs to hex format, then remove 0x from string
	#pad wallet IDs with 0s up to 8 characters
	wID = int(wID)
	wIDHex = hex(wID)
	wIDHex = wIDHex[2:]
	wIDHex = padZeroes(wIDHex, 8)

	wIDB = int(wIDB)
	wIDBHex = hex(wIDB)
	wIDBHex = wIDBHex[2:]
	wIDBHex = padZeroes(wIDBHex, 8)


	#convert amount to hex format, then pad with 0s
	amount = int(amount)
	amountHex = hex(amount)
	amountHex = amountHex[2:]
	amountHex = padZeroes(amountHex, 8)

	#convert counter to hex format, then pad with 0s
	counter = int(counter)
	counterHex = hex(counter)
	counterHex = counterHex[2:]
	counterHex = padZeroes(counterHex, 8)

	#generate token string
	#all values in hex format
	#sender wallet ID, receipient wallet ID, amount, counter
	token = wIDHex + wIDBHex + amountHex + counterHex

	return token



#withdraw money from bank
#emd input must be a JSON formatted string
def bankWithdrawl(kWallet):

	emd = input("Enter Electronic Money Draft token: ")
	plaintext = decryption(emd, kWallet)
	value = int(plaintext.hex(), 16)
	print("Withdrawing: $" + str(value))

	return value



#synchronize 2 wallets
#amount and counter are 0
def syncWallets(walletList, wID, kBank):
	newWallet = True
	wIDBInput = input("Enter 4 digit ID of recipient wallet: ")
	wIDB = wIDBInput[-4:]

	#generate synchronization token
	#amount and counter start at 0
	token = generateToken(wID, wIDB, "0", "0")
	encryption(token, kBank)


	#enter token encrypted with kBank
	receivedTokenEncrypted = input("Enter token sent by recipient wallet: ")
	receivedToken = decryption(receivedTokenEncrypted, kBank)
	receivedTokenString = receivedToken.hex()
	#print(receivedTokenString)

	#parse string for recipient wallet ID and counter
	recipientWallet = receivedTokenString[0:8]
	counter = receivedTokenString[24:32]

	#get 4 digit ID in decimal format, then convert into string
	wIDB = int(recipientWallet, 16)
	wIDB = str(wIDB)

	#check if other wallet already exists in wallet list before synchronizing
	if len(walletList) > 0:
		for i in range(len(walletList)):
			if wIDB == walletList[i][0]:
				newWallet = False
				break

	#if the synchronized wallet is new
	#increment counter to 1, then add to walletList
	if newWallet:
		counter = 1
		newWalletEntry = [wIDB, counter]
		walletList.append(newWalletEntry)


	return walletList



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

#used for generating the bank's secret key
#could not hard code the one from assignment instructions since it needs to be an SHA256 object
bankID = "FSCT8581"
bankID = str.encode(bankID)
kBank = SHA256.new(bankID)



#main menu loop
while option != 0:
	print("\n---------------------------------")
	print("1: Withdraw from bank\n2: Synchronize wallets\n3: Send money\n4: Receive money\n5: Print balance\n6: Exit")
	print("---------------------------------")
	option = input("Select an option: ")
	print("\n")
	if option == "1":
		balance = balance + bankWithdrawl(kWallet)
		print("Balance: $" + str(balance))
	elif option == "2":
		walletList = syncWallets(walletList, wID, kBank)
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


