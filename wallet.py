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
#returns plaintext byte code
def decryption(inputString, key):
	try:
		encryptedJSON = json.loads(inputString)
		iv = b64decode(encryptedJSON['iv'])
		ciphertext = b64decode(encryptedJSON['ct'])
		cipher = AES.new(key.digest(), AES.MODE_CBC, iv)
		plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
	except (ValueError, KeyError):
		print("Decryption failed. Could not withdraw from bank.")

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

	#parse string for recipient wallet ID
	recipientWallet = receivedTokenString[0:8]

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
		print("synchronized wallet: " + wIDB)
	else:
		print("Duplicate wallet. " + str(wIDB) + " was not added to the list of wallets.")

	return walletList



#send money to another wallet
#returns a tuple containing balance and walletList
def sendMoney(wID, amount, balance, kBank, walletList):
	walletExists = False
	index = 0
	wIDB = ""
	amountNum = int(amount)

	#ensure sender is not sending more money than the wallet contains
	if amountNum <= balance:
		wIDB = input("Enter 4 digit recipient wallet ID: ")
		#check if recipient wallet exists in walletList
		for i in range(len(walletList)):
			if wIDB == walletList[i][0]:
				walletExists = True
				index = i
				break

		#send transaction only if wallet exists in walletList
		if walletExists:
			counter = str(walletList[index][1])
			token = generateToken(wID, wIDB, amount, counter)
			encryption(token, kBank)
			balance = balance - amountNum
			walletList[index][1] = walletList[index][1] + 1
			print("Remaining balance: $" + str(balance))
		else:
			print("Recipient wallet is not synchronized.")
	else:
		print("Not enough balance to send this amount.")

	return balance, walletList



#receive money from another wallet
#returns a tuple containing balance and walletList
def receiveMoney(balance, kBank, walletList, wID):
	continueReceive = True
	index = 0

	#enter token, then decrypt it using kBank
	token = input("Enter token to receive funds: ")
	plaintext = decryption(token, kBank)
	plaintext = plaintext.hex()
	#parse out the sender, receiver, amount, and counter from the plaintext
	#they are still hex strings
	sender = plaintext[0:8]
	receiver = plaintext[8:16]
	amount = plaintext[16:24]
	counter = plaintext[24:32]

	#convert sender, receiver, amount, and counter to appropriate formats
	#string, string, int, int
	senderString = int(sender, 16)
	senderString = str(senderString)
	receiverString = int(receiver, 16)
	receiverString = str(receiverString)
	amountNum = int(amount, 16)
	counterNum = int(counter, 16)

	#check if receiver matches this wallet's 4 digit ID
	if wID != receiverString:
		continueReceive = False

	#check if sender is in walletList
	if continueReceive:
		for i in range(len(walletList)):
			if senderString == walletList[i][0]:
				index = i
				break
			else:
					continueReceive = False
					print("Sender's wallet is not synchronized.")

	#check if the counter matches
	#add amount to balance
	#increment counter
	if continueReceive:
		if counterNum == walletList[index][1]:
			balance = balance + amountNum
			walletList[index][1] = walletList[index][1] + 1
		else:
			print("Counter does not match. Cannot deposit money.")

	return balance, walletList



option = 9
balance = 0

#list of synchronized wallets
walletList = []

#8 digit student ID for generate wallet key and getting 4 digit wallet ID
sIDInput = input("Enter 8 digit ID: ")
#student ID in byte format
sID = str.encode(sIDInput)

#last 4 characters of student ID will be the wallet ID
wID = sIDInput[-4:]

#wallet's key. SHA-256 hash of the student number. 32 bits
kWallet = SHA256.new(sID)

#used for generating the bank's secret key
#could not hard code the one from assignment instructions since pycryptodome needs to use an SHA256 object
bankID = "FSCT8581"
bankID = str.encode(bankID)
kBank = SHA256.new(bankID)



#main menu loop
while option != 0:
	print("\n---------------------------------")
	print("1: Withdraw from bank\n2: Synchronize wallets\n3: Send funds\n4: Receive funds\n5: Print balance\n6: Exit")
	print("---------------------------------")
	option = input("Select an option: ")
	print("\n")
	if option == "1":
		balance = balance + bankWithdrawl(kWallet)
		print("Balance: $" + str(balance))

	elif option == "2":
		walletList = syncWallets(walletList, wID, kBank)

	elif option == "3":
		sendAmount = input("Enter amount to send: ")
		if sendAmount.isnumeric():
			balance, walletList = sendMoney(wID, sendAmount, balance, kBank, walletList)
		else:
			print("Input is not numeric")

	elif option == "4":
		balance, walletList = receiveMoney(balance, kBank, walletList, wID)

	elif option == "5":
		print("Balance: $" + str(balance))

	elif option == "6":
		option = 0
		print("Exiting\n")

	else:
		print("Invalid input\n")


