from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Sign
from Crypto import Random
from Crypto.Hash import SHA256
from binascii import unhexlify
from tabulate import tabulate
import sys
import os
import time
import mariadb
import getpass

os.system('color B')
clear = lambda: os.system('cls')
Title = "    ___       __          _       __  _______  ____ \n" \
		"   /   | ____/ /___ ___  (_)___  /  |/  / __ \/ __ \ \n" \
		"  / /| |/ __  / __ `__ \/ / __ \/ /|_/ / /_/ / /_/ /\n" \
		" / ___ / /_/ / / / / / / / / / / /  / / _, _/ _, _/ \n" \
		"/_/  |_\__,_/_/ /_/ /_/_/_/ /_/_/  /_/_/ |_/_/ |_|  \n"

def countVotes():

	# Retrieve keys
	print("Retrieving encryption and decryption keys...")
	cur.execute("SELECT Key_N, Key_E, Key_D FROM `keys`;")
	for c in cur:
		n = c[0]
		e = c[1]
		d = c[2]
	N = int(n, 16)
	E = int(e, 16)
	D = int(d, 16)
	keyPair = RSA.construct((N, E, D))
	pubKey = keyPair.publickey()
	priKey = keyPair.export_key()
	dsize = SHA256.digest_size
	sentinel = Random.new().read(1024+dsize)
	decryptor = PKCS1_v1_5.new(keyPair)

	# Retrieve votes + signatures
	print("Retrieving encrypted votes...")
	print("Retrieving encrypted signatures...")
	cur.execute("SELECT * FROM `election` ")
	listVotes = []
	for e in cur.fetchall():
		listVotes.append((e[1], e[2], e[3]))

	# Vote + signature decryption
	print("Decrypting votes...")
	print("Decrypting signatures...")
	listVotesDecrypted = []
	for l in listVotes:
		vote = decryptor.decrypt(unhexlify(l[0]), sentinel)
		sign1 = decryptor.decrypt(unhexlify(l[1]), sentinel).hex()
		sign2 = decryptor.decrypt(unhexlify(l[2]), sentinel).hex()
		listVotesDecrypted.append((vote, sign1+sign2))

	verification = PKCS1_v1_5_Sign.new(keyPair)

	# Counting votes
	print("Verifying signatures...")
	countIDs = []
	countNames = []
	countVotes = []
	countTotal = []
	for ld in listVotesDecrypted:
		h = SHA256.new(ld[0])
		if verification.verify(h, unhexlify(ld[1])):
			if ld[0].decode('utf8') not in countIDs:
				countIDs.append(ld[0].decode('utf8'))
				cur.execute("SELECT `First Name`, `Name` FROM `candidates` WHERE `ID_Candidates` = '"+ld[0].decode('utf8')+"';")
				for c in cur:
					countNames.append((ld[0].decode('utf8'), c[0], c[1]))
			countVotes.append(ld[0].decode('utf8'))
		else:
			print("Corrupted vote!!! Please look at the database!")

	print("Counting all the votes...")
	for c in countNames:
		numberOfVotes = countVotes.count(c[0])
		countTotal.append((c[1], c[2], numberOfVotes))

	countTotal.sort(key=lambda tup: tup[2], reverse=True)

	print("Displaying voting table...")
	time.sleep(3)
	clear()
	print(Title)

	print(tabulate(countTotal, headers=["First Name", "Last Name", "N° of votes"], tablefmt='fancy_grid',
				   colalign=("center",)))


if __name__ == '__main__':
	print(Title)
	print("Press enter to start...", end="")
	input()
	print("Please enter the password to gain access to the database.")
	while True:
		try:
			password = getpass.getpass(prompt=">>> ")
			if password == "stop":
				print("Exiting")
				sys.exit(0)
			connectionMariaDB = mariadb.connect(
				user = "MauRafRem",
				password = password,
				host = "127.0.0.1",
			)
			print("Welcome")
			cur = connectionMariaDB.cursor()
			cur.execute("USE voting_system;")
			countVotes()
			print("Press enter to exit...", end="")
			input()
			break
		except mariadb.Error as e:
			print("Wrong password! Try again.")
			continue