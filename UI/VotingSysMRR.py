from smartcard.CardType import ATRCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString, toBytes
from smartcard.Exceptions import *
import mariadb
import sys
import os
import datetime
import time
import getpass
from tabulate import tabulate

# from tabulate import tabulate
os.system('color B')
clear = lambda: os.system('cls')
Title = " _    __      __  _                _____            __  _______  ____ \n" \
		"| |  / /___  / /_(_)___  ____ _   / ___/__  _______/  |/  / __ \/ __ \ \n" \
		"| | / / __ \/ __/ / __ \/ __ `/   \__ \/ / / / ___/ /|_/ / /_/ / /_/ /\n" \
		"| |/ / /_/ / /_/ / / / / /_/ /   ___/ / /_/ (__  ) /  / / _, _/ _, _/ \n" \
		"|___/\____/\__/_/_/ /_/\__, /   /____/\__, /____/_/  /_/_/ |_/_/ |_|  \n" \
		"                      /____/         /____/                           \n"


def initialize():
	def hasNumbers(inputString):
		return any(char.isdigit() for char in inputString)

	def hasSpecialCharacters(inputString):
		special_characters = "!@#$%^&*()+?_=,<>/"
		return any(c in special_characters for c in inputString)

	print("Welcome to the VotingSysMRR card initialization! Please do not remove your card during this process.\n\n")

	while True:

		# First name
		print("Please enter your first name (type 'stop' to exit)")
		while True:
			firstName = input(">>> ")
			if len(firstName) > 30:
				print("Too long. Please try again.")
				continue
			elif hasNumbers(firstName):
				print("Do not include any numbers! Please try again.")
				continue
			elif hasSpecialCharacters(firstName):
				print("Do not include any special characters except for ' and - ! Please try again.")
				continue
			elif firstName == "stop":
				print("Exiting")
				return
			else:
				break

		# First name
		print("Please enter your last name (type 'stop' to exit)")
		while True:
			lastName = input(">>> ")
			if len(lastName) > 30:
				print("Too long. Please try again.")
				continue
			elif hasNumbers(lastName):
				print("Do not include any numbers! Please try again.")
				continue
			elif hasSpecialCharacters(lastName):
				print("Do not include any special characters except for ' and - ! Please try again.")
				continue
			elif lastName == "stop":
				print("Exiting...")
				return
			else:
				break

		# Sex
		print("Please enter your sex (M/F) (type 'stop' to exit)")
		while True:
			sex = input(">>> ")
			if len(sex) > 1:
				print("Enter only one character (M/F)! Please try again.")
				continue
			elif sex.lower() != "m" and sex.lower() != "f":
				print("Enter either 'M' or 'F'! Please try again.")
				continue
			elif sex == "stop":
				print("Exiting...")
				return
			else:
				break

		# Birthdate
		print("Please enter your birthdate (dd/mm/yyyy) (type 'stop' to exit)")
		while True:
			try:
				birthDate = input(">>> ")
				if lastName == "stop":
					print("Exiting...")
					return
				b = datetime.datetime.strptime(birthDate, '%d/%m/%Y')
				birthdate = b.date().__str__()
				break
			except Exception as e:
				print("Enter a valid date! Please try again.")

		# PIN
		print("Please enter your 5-digit pin (type 'stop' to exit)")
		while True:
			pin = getpass.getpass(prompt=">>> ")
			if len(pin) != 5:
				print("The PIN needs to be 5 digits long! Please try again.")
				continue
			if pin == "stop":
				print("Exiting")
				sys.exit(0)
			elif not (pin.isnumeric()):
				print("Only enter digits! Please try again.")
				continue
			else:
				break

		print()
		print("Your information:")
		print("> First name: {0}\n"
			  "> Last name:  {1}\n"
			  "> Sex:        {2}\n"
			  "> Birthdate:  {3}\n"
			  "> Pin:        {4}".format(firstName, lastName, sex, birthDate, '*' * len(pin)))

		print("Is this information correct? (Y/N)")
		while True:
			confirm = input(">>> ")
			if len(confirm) > 1:
				print("Enter only one character (Y/N)! Please try again.")
				continue
			if confirm.lower() == "y" or confirm.lower():
				break

		if confirm.lower() == "n":
			clear()
			print(Title)
			continue
		elif confirm.lower() == "y":
			sendInitializationAPDUs(firstName, lastName, sex, birthDate, pin)
			add_account(firstName, lastName, sex, birthdate)
			break


def sendInitializationAPDUs(firstName, lastName, sex, birthDate, pin):
	# First name
	REG_FIRST_NAME_DATA = [ord(f) for f in firstName]
	REG_FIRST_NAME = toBytes("B0 01 00 00 " + format(len(REG_FIRST_NAME_DATA), '#04x')[2:]
							 + toHexString(REG_FIRST_NAME_DATA) + "00")
	data, sw1, sw2 = cardservice.connection.transmit(REG_FIRST_NAME)

	# Last name
	REG_LAST_NAME_DATA = [ord(f) for f in lastName]
	REG_LAST_NAME = toBytes("B0 02 00 00 " + format(len(REG_LAST_NAME_DATA), '#04x')[2:]
							+ toHexString(REG_LAST_NAME_DATA) + "00")
	data, sw1, sw2 = cardservice.connection.transmit(REG_LAST_NAME)

	# Sex
	sToByte = {'m': 0, 'f': 1}
	REG_SEX = toBytes("B0 03 00 00 01" + format(sToByte[sex.lower()], '#04x')[2:] + "00")
	data, sw1, sw2 = cardservice.connection.transmit(REG_SEX)

	# Birthdate
	birthdate = datetime.datetime.strptime(birthDate, '%d/%m/%Y')
	day = birthdate.day
	month = birthdate.month
	y1, y2 = format(birthdate.year, '#04')[0:2], format(birthdate.year, '#04')[2:4]
	REG_BIRTH_DATE = toBytes("B0 04 00 00 04 " + format(day, '#04x')[2:] + format(month, '#04x')[2:]
							 + format(int(y1), '#04x')[2:] + format(int(y2), '#04x')[2:] + "00")
	data, sw1, sw2 = cardservice.connection.transmit(REG_BIRTH_DATE)

	# PIN
	pinList = [int(p) for p in pin]
	UPDATE_PIN = toBytes("B0 09 00 00 05" + toHexString(pinList) + "00")
	data, sw1, sw2 = cardservice.connection.transmit(UPDATE_PIN)

	# Initialization
	INITIALIZE = toBytes("B0 0C 00 00 00 00")
	data, sw1, sw2 = cardservice.connection.transmit(INITIALIZE)

	# Set keys
	cur.execute("SELECT Key_N, Key_E, Key_D FROM `keys`;")
	for c in cur:
		n = c[0]
		e = c[1]
		d = c[2]
	SET_RSA_PUBKEY = toBytes("B0 33 00 00 83" + n + e)
	data, sw1, sw2 = cardservice.connection.transmit(SET_RSA_PUBKEY)
	SET_RSA_PRIKEY_1 = toBytes("B0 34 80 00 C8" + n + d[:144])
	SET_RSA_PRIKEY_2 = toBytes("B0 34 00 01 38" + d[144:])
	data, sw1, sw2 = cardservice.connection.transmit(SET_RSA_PRIKEY_1)
	data, sw1, sw2 = cardservice.connection.transmit(SET_RSA_PRIKEY_2)

	# get
	GET_CARD_ID = toBytes("B0 0E 00 00 00 08")
	data, sw1, sw2 = cardservice.connection.transmit(GET_CARD_ID)
	cardID = data[0:8]
	cardID[0] = chr(cardID[0])
	cardID[1] = chr(cardID[1])
	for i in range(2, 6):
		cardID[i] = str(cardID[i])
	cardID[6] = format(cardID[6], '#04x')[2:].upper()
	cardID[7] = format(cardID[7], '#04x')[2:].upper()
	print("Card ID >>> ", ''.join(cardID))
	print()
	print("The initialization process is done. Remove your card once this program stops.")
	time.sleep(3)


def add_account(firstName, lastName, sex, birthdate):
	GET_CARD_ID = toBytes("B0 0E 00 00 00 08")
	data, sw1, sw2 = cardservice.connection.transmit(GET_CARD_ID)
	cardID = data[0:8]
	cardID[0] = chr(cardID[0])
	cardID[1] = chr(cardID[1])
	for i in range(2, 6):
		cardID[i] = str(cardID[i])
	cardID[6] = format(cardID[6], '#04x')[2:].upper()
	cardID[7] = format(cardID[7], '#04x')[2:].upper()
	cardID = ''.join(cardID)
	cur.execute("USE voting_system;")
	cur.execute("INSERT INTO `voter`(`ID_Voter`, `First Name`, `Name`, `sexe`, `Date_of_birth`, `Right_of_vote`) VALUES ('"+cardID+"','"+firstName+"', '"+lastName+"', '"+sex+"', '"+birthdate+"', True);")


def displayInformation():

	GET_FIRST_NAME = toBytes("B0 05 00 00 00 7F")
	data, sw1, sw2 = cardservice.connection.transmit(GET_FIRST_NAME)
	firstName = "".join([chr(d) for d in data if d != 0])

	GET_LAST_NAME = toBytes("B0 06 00 00 00 7F")
	data, sw1, sw2 = cardservice.connection.transmit(GET_LAST_NAME)
	lastName = "".join([chr(d) for d in data if d != 0])

	GET_BIRTH_DATE = toBytes("B0 07 00 00 00 7F")
	data, sw1, sw2 = cardservice.connection.transmit(GET_BIRTH_DATE)
	birthDate = str(data[0]) + "/" + str(data[1]) + "/" + str(data[2]) + str(data[3])

	GET_SEX_VALUE = toBytes("B0 08 00 00 00 7F")
	data, sw1, sw2 = cardservice.connection.transmit(GET_SEX_VALUE)
	s = {0: 'M', 1: 'F'}
	sex = s[data[0]]

	GET_CARD_ID = toBytes("B0 0E 00 00 00 08")
	data, sw1, sw2 = cardservice.connection.transmit(GET_CARD_ID)
	cardID = data[0:8]
	cardID[0] = chr(cardID[0])
	cardID[1] = chr(cardID[1])
	for i in range(2, 6):
		cardID[i] = str(cardID[i])
	cardID[6] = format(cardID[6], '#04x')[2:].upper()
	cardID[7] = format(cardID[7], '#04x')[2:].upper()
	cardID = "".join(cardID)

	print("Your information:")
	print("> First name: {0}\n"
		  "> Last name:  {1}\n"
		  "> Sex:        {2}\n"
		  "> Birthdate:  {3}\n"
		  "> Card ID:    {4}".format(firstName, lastName, sex, birthDate, cardID))


def vote(ID):
	cur.execute("SELECT * FROM `voter` WHERE `ID_Voter` = '"+cardID+"';")
	user = list(cur)
	rightToVote = user[0][5]
	if rightToVote == 0:
		print("You are no longer eligible to vote. Exiting now...")
		time.sleep(3)
		return
	else:
		cur.execute("SELECT * FROM `candidates` ")
		i = 1
		List_candidate ={}
		List_candidate_UI = {}
		for show in cur.fetchall():
			List_candidate[i] = show
			List_candidate_UI[i] = (show[1], show[2], show[3], show[4])
			i += 1
		print(tabulate([(k,) + v for k, v in List_candidate_UI.items()], headers=["First Name", "Last Name", "Electoral Party", "Age"],
			  tablefmt='fancy_grid', colalign=("center",)))
		while True:
			print("Please enter the number of the candidate you would like to vote for.")
			try:
				voteChoice = input(">>> ")
				vote = List_candidate[int(voteChoice)][0]
				print("Please wait while we are processing your vote. Do not remove your card!")
				break
			except Exception as e:
				print("Enter a valid number! Please try again.")
				continue

		# Encrypting the vote
		voteList = [ord(v) for v in vote]
		ENCRYPT_VOTE = toBytes("B0 37 00 00" + format(len(voteList), "#04x")[2:] + toHexString(voteList) + "7F")
		data, sw1, sw2 = cardservice.connection.transmit(ENCRYPT_VOTE)
		encrypted_vote = "".join([format(d, "#04x")[2:] for d in data])

		# Signing the vote
		RSA_SIGN = toBytes("B0 35 00 00" + format(len(voteList), "#04x")[2:] + toHexString(voteList) + "7F")
		data, sw1, sw2 = cardservice.connection.transmit(RSA_SIGN)
		signaturePart1 = "".join([format(d, "#04x")[2:] for d in data[:117]])
		signaturePart2 = "".join([format(d, "#04x")[2:] for d in data[117:]])

		# Encrypting the signature
		ENCRYPT_SIGNATURE_PART_1 = toBytes("B0 37 00 00 75" + signaturePart1 + "7F")
		ENCRYPT_SIGNATURE_PART_2 = toBytes("B0 37 00 00 0B" + signaturePart2 + "7F")
		data, sw1, sw2 = cardservice.connection.transmit(ENCRYPT_SIGNATURE_PART_1)
		encrypted_signaturePart1 = "".join([format(d, "#04x")[2:] for d in data])
		data, sw1, sw2 = cardservice.connection.transmit(ENCRYPT_SIGNATURE_PART_2)
		encrypted_signaturePart2 = "".join([format(d, "#04x")[2:] for d in data])

		# Sending the encrypted vote and encrypted signature
		sendVote(encrypted_vote, encrypted_signaturePart1, encrypted_signaturePart2, ID)
		print("Thank you for voting! You can remove your card now. The program will automatically close.")
		time.sleep(5)


def sendVote(enc_vote, enc_sign1, enc_sign2, ID):
	cur.execute("INSERT INTO `election`(`ID_Candidates`, `ID_signature_1`, `Id_signature_2`, `Date_of_the_vote`) "
				"VALUES ('"+enc_vote+"', '"+enc_sign1+"', '"+enc_sign2+"', '"+str(datetime.date.today())+"');")
	# Removing the user's right to vote
	cur.execute("UPDATE `voter` SET `Right_of_vote`= False WHERE `ID_Voter`= '"+ID+"'")





if __name__ == '__main__':

	clear()
	print(Title)
	print("Press enter to start...", end="")
	input()

	# Checking the card is inserted into the reader
	cardtype = ATRCardType(toBytes("3B 90 95 80 11 FE 6A"))
	cardrequest = CardRequest(timeout=15, cardType=cardtype)

	print("Please insert your card...")
	try:
		cardservice = cardrequest.waitforcard()
		print("Card connected!")
		cardservice.connection.connect()
	except CardRequestTimeoutException as CRTE:
		print("Card has not been inserted. Exiting now.")
		sys.exit(1)

	SELECT = toBytes("00 A4 04 00 06 99 99 99 99 99 00 00")
	data, sw1, sw2 = cardservice.connection.transmit(SELECT)
	print()

	# Checking if the connection to the mariadb database works fine
	try:
		connectionMariaDB = mariadb.connect(
			user = "MauRafRem",
			password = "votingsysmrr123",
			host = "127.0.0.1",
		)
		cur = connectionMariaDB.cursor()
		cur.execute("USE voting_system;")
	except mariadb.Error as e:
		print("Error connecting to MariaDB Platform: {}".format(e))
		sys.exit(1)

	try:
		IS_INITIALIZED = toBytes("B0 0D 00 00 00 01")
		data, sw1, sw2 = cardservice.connection.transmit(IS_INITIALIZED)
		is_initialized = data[0]
	except IndexError:
		print("Your card is blocked. Please contact a technician to solve any problems with your card.")
		print("Exiting now...")
		time.sleep(5)
		sys.exit(0)

	if is_initialized == 0:
		clear()
		print(Title)
		initialize()
	else:
		print("Please enter your pin! (type 'stop' to exit)")
		while True:
			pinAttempt = getpass.getpass(prompt=">>> ")
			if pinAttempt == "stop":
				print("Bye!")
				sys.exit(0)
			elif not (pinAttempt.isnumeric()):
				print("Only enter digits! Please try again.")
				continue
			if len(pinAttempt) != 5:
				print("The pin needs to be 5 digits long! Please try again.")
				continue
			else:
				pinAttemptList = [int(p) for p in pinAttempt]
				VERIFY_PIN = toBytes("B0 0A 00 00 05" + toHexString(pinAttemptList) + "00")
				data, sw1, sw2 = cardservice.connection.transmit(VERIFY_PIN)
				if sw1 == 0x90 and sw2 == 0x00:
					clear()
					print(Title)
					break
				else:
					GET_PIN_ATTEMPTS = toBytes("B0 0F 00 00 00 01")
					data, sw1, sw2 = cardservice.connection.transmit(GET_PIN_ATTEMPTS)
					attemptsRemaining = data[0]
					print("Wrong pin! You have {} tries remaining!".format(attemptsRemaining))
					if attemptsRemaining == 0:
						print("Your card is now blocked. Please contact a technician to solve any problems with your card.")
						print("Exiting now...")
						time.sleep(5)
						sys.exit(0)
					continue

		GET_FIRST_NAME = toBytes("B0 05 00 00 00 7F")
		data, sw1, sw2 = cardservice.connection.transmit(GET_FIRST_NAME)
		firstName = "".join([chr(d) for d in data if d != 0])
		GET_LAST_NAME = toBytes("B0 06 00 00 00 7F")
		data, sw1, sw2 = cardservice.connection.transmit(GET_LAST_NAME)
		lastName = "".join([chr(d) for d in data if d != 0])
		GET_CARD_ID = toBytes("B0 0E 00 00 00 08")
		data, sw1, sw2 = cardservice.connection.transmit(GET_CARD_ID)
		cardID = data[0:8]
		cardID[0] = chr(cardID[0])
		cardID[1] = chr(cardID[1])
		for i in range(2, 6):
			cardID[i] = str(cardID[i])
		cardID[6] = format(cardID[6], '#04x')[2:].upper()
		cardID[7] = format(cardID[7], '#04x')[2:].upper()
		cardID = "".join(cardID)
		print("Welcome {0} {1}! (ID: {2})".format(firstName, lastName, cardID))
		while True:
			print("What would you like to do?\n1> Display information\n2> Vote\n3> Exit")
			option = input(">>> ")
			if option == "1":
				clear()
				print(Title)
				displayInformation()
				print("Press enter to continue...", end="")
				input()
				clear()
				print(Title)
				continue
			elif option == "2":
				clear()
				print(Title)
				vote(cardID)
				break
			elif option == "3":
				print("Bye!")
				sys.exit(0)
			else:
				print("Enter either 1, 2 or 3! Please try again.")
				continue
		cardservice.connection.disconnect()