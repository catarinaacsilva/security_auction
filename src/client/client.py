import os
import socket
import json
import base64
import sys
import platform
import subprocess
import hashlib
import getpass
from multiprocessing import Process
from ..common.utils import *
from ..common.cartaodecidadao import CartaoDeCidadao
from ..common.dynamiccode import DynamicCode
from ..common.receiptmanager import ReceiptManager
from ..common.certmanager import CertManager
from ..common.cryptopuzzle import CryptoPuzzle
from ..common.cryptmanager import *
from ..common.logger import initialize_logger

logging = initialize_logger('AC', "src/client")

colors = {
		'blue': '\033[94m',
		'pink': '\033[95m',
		'green': '\033[92m',
		'red' : '\033[91m'
		}

UDP_IP = "127.0.0.1"				# Assuming the servers will be local
UDP_PORT_MANAGER = 5001				# Port used for communication with auction manager
UDP_PORT_REPOSITORY = 5002			# Port used for communication with auction repository

# Socket used for communication with manager
sock_manager = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock_manager.connect((UDP_IP, UDP_PORT_MANAGER))

# Socket used for communication with repository
sock_repository = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock_repository.connect((UDP_IP, UDP_PORT_REPOSITORY))

cc = CartaoDeCidadao()
auction_list = []


def verify_server(certificate, message, signature):
	'''
		Verify Server Certificate and Signature
	'''

	certificate = fromBase64(certificate)
	signature = fromBase64(signature)
	cm = CertManager(cert = certificate)
	return  cm.verify_certificate() and cm.verify_signature( signature , message )

def wait_for_answer(sock, action):
	'''
		Waits for a response from server
	'''
	sock.settimeout(3)
	while True:
		try:
			data, addr = sock.recvfrom(8192)
			if data:
				answer = json.loads(data.decode('UTF-8'))
				if(answer["ACTION"] == action):
					return answer
				else:
					logging.error("Server sent an Invalid JSON!: " + data)
		except socket.timeout:
			logging.error("Answer from server timedout (must likely an error occurred).")
			input("Answer from server timed out. Press any key to continue...")
			return False
		except:
			logging.error("Failed to connect to server or server sent an invalid JSON!")
			return False

	print( colorize("Unable to connect with server, please try again later.", 'red') )
	input("Press any key to continue...")
	return False

def reclaim(arg):
	'''
		Reclaim your prize (WIP)
	'''

	# Reading arguments
	auction_id = arg[0]
	is_english = arg[1]

	# Scanning user CartaoDeCidadao
	logging.info("Reading User's Cartao De Cidadao")
	print( colorize( "Reading Citizen Card, please wait...", 'pink' ) )
	cc.scan()
	clean(lines = 1)
	logging.info("Trying to establishing connection with server")

	# Sending challenge to the server
	challenge = os.urandom(64)
	connection = {"ACTION": "CHALLENGE", "CHALLENGE":  toBase64(challenge)  ,\
	 			  "CERTIFICATE": toBase64(cc.get_certificate_raw()) }
	sock_repository.send( json.dumps(connection).encode("UTF-8") )
	logging.info("Sent Challenge To Server: " + json.dumps(connection))

	# Wait for Challenge Response
	server_answer = wait_for_answer(sock_repository , "CHALLENGE_REPLY")
	if not server_answer: return
	logging.info("Received Challenge Response: " + json.dumps(server_answer))

	# Verify server certificate, verify signature of challenge and decode NONCE
	logging.info("Verifying certificate and server signature of challenge")
	if not verify_server( server_answer['CERTIFICATE'], challenge, server_answer['CHALLENGE_RESPONSE'] ):
		logging.warning("Server Verification Failed")
		print( colorize('Server Validation Failed!', 'red') )
		input("Press any key to continue...")
		return

	rm = ReceiptManager(cc)
	bids = rm.get_receipt_value(str(auction_id), not is_english)
	if bids == []:
		input( colorize( "You have no bids at this auction. Press any key to continue...", 'red' ) )
		return

	# Printing existing bids
	while(True):
		print( colorize( "Which Bid would you like to reclaim?", 'pink' ) )
		for bid in bids:
			print(str(bids.index(bid)+1) + " - "+ colorize(bid[0] + '€', 'red'))
		choice = input(">> ")
		if int(choice) <= len(bids) and int(choice) > 0:
			break
		else:
			print( colorize('Invalid Option!', 'red') )
			clean(lines=len(bids)+3)

	logging.info("Building RECLAIM message")
	print( colorize( "Sending Request, please wait...", 'pink' ) )
	chosen_one = bids[int(choice)-1]
	receipt = json.loads(rm.get_receipt(str(auction_id)+'-'+str(chosen_one[1])))
	receipt.pop('KEY', None)

	message = {
					"RECEIPT" : receipt,
					"NONCE" : server_answer["NONCE"]
			   }

	outter = {
					"ACTION" : "RECLAIM",
					"MESSAGE" : message,
					"CERTIFICATE" : toBase64(cc.get_certificate_raw()),
					"SIGNATURE" : toBase64(cc.sign( json.dumps(message).encode('UTF-8') ))
			}

	logging.info("Sending RECLAIM message to repository: " + json.dumps(outter))
	sock_repository.send( json.dumps(outter).encode("UTF-8") )

	# Wait for Server Response
	logging.info("Waiting for server response")
	server_answer = wait_for_answer(sock_repository, "RECLAIM_REPLY")
	if not server_answer: return
	logging.info("Received Server Response: " + json.dumps(server_answer))

	if (server_answer["STATE"] == "OK"):
		clean(lines=1)
		logging.info("Prize was reclaimed successfully")
		print( colorize("Prize successfully reclaimed. Auction Owner will contact you sortly", 'pink') )
		input("Press any key to continue...")
	elif (server_answer["STATE"] == "NOT OK"):
		clean(lines=1)
		logging.info("Prize reclaim failed : " + server_answer["ERROR"] )
		print( colorize("ERROR: " + server_answer["ERROR"], 'red') )
		input("Press any key to continue...")
	else:
		clean(lines=1)
		logging.info("Auction Creating Failed With Unexpected Error ")
		print( colorize("Something really weird happen, please fill a bug report.", 'red') )
		input("Press any key to continue...")

def create_new_auction(*arg):
	'''
		Creates new auction via auction manager

		JSON sent to Auction Manager Description:

		OUTTER:

		{
			"ACTION" : "CREATE",		# Action we intend auction manager to do, just for easier reading on server-side
			"MESSAGE" : {},				# JSON with all the action description (described bellow)
			"SIGNATURE" : "____",		# Message Signed with CC card
		}

		MESSAGE:

		{
			"ACTION" : "CREATE",		# Action we intend auction manager to do, just for easier reading on server-side
			"TITLE": "_____",			# Title of the auction
			"DESCRIPTION": "_____",		# Description of the auction
			"TYPE": ___,				# Type of the auction 1 being english auction and 2 being blind auction
			"SUBTYPE": ___,				# SubType of the auction, as if it hides the identity or not
			"AUCTION_EXPIRES": ___,		# Expiration of Auction is hours
			"CODE": ___,				# Dynamic code that user wrote
			"NONCE": ___,				# NONCE given by the server
		}
	'''
	# Scanning user CartaoDeCidadao
	logging.info("Reading User's Cartao De Cidadao")
	print( colorize( "Reading Citizen Card, please wait...", 'pink' ) )
	cc.scan()
	clean(lines = 1)

	# Establish connection with server
	print( colorize( "Establishing connection with server, please wait...", 'pink' ) )
	logging.info("Trying to establishing connection with server")

	# Sending challenge to the server
	challenge = os.urandom(64)
	connection = {"ACTION": "CHALLENGE", "CHALLENGE":  toBase64(challenge)  ,\
	 			  "CERTIFICATE": toBase64(cc.get_certificate_raw()) }
	sock_manager.send( json.dumps(connection).encode("UTF-8") )
	logging.info("Sent Challenge To Server: " + json.dumps(connection))

	# Wait for Challenge Response
	server_answer = wait_for_answer(sock_manager , "CHALLENGE_REPLY")
	if not server_answer: return
	logging.info("Received Challenge Response: " + json.dumps(server_answer))

	# Verify server certificate, verify signature of challenge and decode NONCE
	logging.info("Verifying certificate and server signature of challenge")
	if not verify_server( server_answer['CERTIFICATE'], challenge, server_answer['CHALLENGE_RESPONSE'] ):
		logging.warning("Server Verification Failed")
		print( colorize('Server Validation Failed!', 'red') )
		input("Press any key to continue...")
		return

	new_auction = {}

	clean(lines = 1)

	# Auction Title
	while True:
		new_auction["TITLE"] = input("Title: ")
		if new_auction['TITLE'] != "":
			clean(True)
			break
		else:
			print( colorize('Title can\'t be empty!', 'red') )
			clean()

	# Auction Description
	while True:
		new_auction['DESCRIPTION'] = input("Description: ")
		if new_auction['DESCRIPTION'] != "":
			clean(True)
			break
		else:
			print( colorize('Description can\'t be empty!', 'red') )
			clean()

	# Auction Type
	while True:
		print(colorize('Types available: \n 	1 - English Auction (Public Values) \n 	2 - Blind Auction (Hidden Values Revealed at the end)', 'green'))
		try:
			new_auction['TYPE'] = int(input("Type: "))
		except ValueError:
			print( colorize('Type must be a number!', 'red') )
			clean(lines=5)
			continue
		else:
			if new_auction['TYPE'] == 1 or new_auction['TYPE'] == 2:
				clean(True)
				break
			else:
				print( colorize('Please pick one of the available types.', 'red') )
				clean(lines=5)

	# Auction SubType
	while True:
		if new_auction['TYPE'] == 1:
			# English Auction must have hidden identity
			new_auction['SUBTYPE'] = 2
			break
		print(colorize('SubTypes available: \n 	1 - Public Identity\n 	2 - Hidden Identity [until end of auction]', 'green'))
		try:
			new_auction['SUBTYPE'] = int(input("SubType: "))
		except ValueError:
			print( colorize('SubType must be a number!', 'red') )
			clean(lines=5)
			continue
		else:
			if new_auction['SUBTYPE'] == 1 or new_auction['SUBTYPE'] == 2:
				clean(True)
				break
			else:
				print( colorize('Please pick one of the available subtypes.', 'red') )
				clean(lines=5)

	# Time for Auction expiration (hours)
	while True:
		try:
			new_auction['AUCTION_EXPIRES'] = int(input("Expiration time for Auction (seconds): "))
		except ValueError:
			print( colorize('Expiration must be a number!', 'red') )
			clean()
			continue
		else:
			if new_auction['AUCTION_EXPIRES'] >= 0:
				clean(True)
				break
			else:
				print( colorize('Please pick a positive number.', 'red') )
				clean()

	# Dynamic Code For Bid Validation
	print("Do you wish to upload code for bid validation?")
	choice = input("[y/N] => ")
	choice = choice.upper()

	clean(lines=1)
	clean(lines=1)

	if(choice.startswith("Y")):
		plat = platform.system()
		try:
			# linux platform
			if(plat == "Linux"): subprocess.call(['xdg-open', 'src/client/code.txt'])
			# mac platform
			elif(plat == "Darwin"): subprocess.call(['open', 'src/client/code.txt'])
			# windows platform
			elif(plat == "Windows"): os.startfile('src/client/code.txt')
			else:
				print("Please Edit Code To Upload on code.txt file.")
		except:
			print( colorize("ERROR: Unable to open code upload file.", 'red') )
			quit()

		print(colorize("File for dynamic code will open sortly... please wait.", 'pink' ))
		while True:
			input("Press any key when code is ready to upload...")
			clean(lines=1)
			clean(lines=1)
			# Reading code, removing comments and validate it
			with open('src/client/code.txt', 'r') as f:
				code = [line for line in f if not line.startswith("#")]
				code = ''.join(str(elem) for elem in code)
				code_check = DynamicCode.check_code(code)
				if code_check[0]:
					new_auction["CODE"] = code
					break
				else:
					print(colorize("DynamicCode not valid, try again: " + str(code_check[1]), 'red'))

	# Building INNER JSON
	new_auction["ACTION"] = "CREATE"
	new_auction["NONCE"] = server_answer["NONCE"]
	new_auction = json.dumps(new_auction)

	# Signing and creating OUTTER layer of JSON message
	logging.info("Signing Message To Send Server")
	signed_message = cc.sign( new_auction.encode('UTF-8') )
	outter_message = {"SIGNATURE": toBase64( signed_message ),
				      "MESSAGE" : new_auction,
					  "ACTION" : "CREATE" }

	# Sending New Auction Request For Auction Manager
	logging.info("Sending Request To Server:" + json.dumps(outter_message))
	sock_manager.send( json.dumps(outter_message).encode("UTF-8") )

	# Wait for Server Response
	logging.info("Waiting for server response")
	print( colorize( "Creating Auction, please wait...", 'pink' ) )
	server_answer = wait_for_answer(sock_manager, "CREATE_REPLY")
	if not server_answer: return
	logging.info("Received Server Response: " + json.dumps(server_answer))

	if (server_answer["STATE"] == "OK"):
		clean(lines=1)
		logging.info("Auction Creating Was Successful")
		print( colorize("Auction successfully created!", 'pink') )
		input("Press any key to continue...")
	elif (server_answer["STATE"] == "NOT OK"):
		clean(lines=1)
		logging.info("Auction Creating Failed : " + server_answer["ERROR"] )
		print( colorize("ERROR: " + server_answer["ERROR"], 'red') )
		input("Press any key to continue...")
	else:
		clean(lines=1)
		logging.info("Auction Creating Failed With Unexpected Error ")
		print( colorize("Something really weird happen, please fill a bug report.", 'red') )
		input("Press any key to continue...")


def list_auction(arg):
	'''
		Requests auctions to auction repository

		JSON sent to Auction Repository Description:

		{
			"ACTION" : "LIST",
			"NONCE"  : _______________
			(Optional) "AUCTION_ID" : XX
		}
	'''

	auction_id = arg[0] if 0 < len(arg) else None
	return_value = arg[1] if 1 < len(arg) else False

	request = {"ACTION" : "LIST"}
	# If filtering information
	if auction_id:
		request["AUCTION_ID"] = auction_id

	# Nonce for server
	nonce = os.urandom(64)
	request["NONCE"] = toBase64(nonce)
	# Covert to JSON string
	request = json.dumps(request)
	# Send request to repository
	sock_repository.send(request.encode("UTF-8"))
	# Waiting for server response
	server_answer = wait_for_answer(sock_repository, "LIST_REPLY")
	if not server_answer: return

	'''
		Expected answer

		IF AUCTION_ID NOT GIVEN:
		{
			'CERTIFICATE' : ____,
			'SIGNATURE' : ____, (of 'MESSAGE')
			'MESSAGE' : {
							"NONCE" : ____,
							"LIST" : [{'TITLE':__, 'AUCTION_ID':___},{'TITLE':__, 'AUCTION_ID':___},...],
						}
		}

		IF GIVEN AUCTION_ID:
		{
			'CERTIFICATE' : ____,
			'SIGNATURE' : ____, (of 'MESSAGE')
			'MESSAGE' : {
							"NONCE" : ____,
							"AUCTION" : {
											"AUCTION_ID" : ____,
											"TITLE" : _____,
											"DESCRIPTION" : _____,
											"TYPE" : _____,
											"SUBTYPE" : ____,
											"ENDING_TIMESTAMP" : ____,
											"BIDS" : []
										}
						}
		}
	'''

	# Verify server certificate and verify signature of auction list
	challenge = json.dumps(server_answer['MESSAGE']).encode('UTF-8')
	if not verify_server(server_answer['CERTIFICATE'], challenge, server_answer['SIGNATURE'] ) \
		or not fromBase64(server_answer['MESSAGE']['NONCE']) == nonce:
		print( colorize('Server Validation Failed!', 'red') )
		input()
		return

	# In case of getting a list of auctions
	if not auction_id or isinstance(auction_id, (list,)):
		auctions = []
		auction_list = server_answer['MESSAGE']['LIST']
		if return_value: return auction_list
		# test subject comment line above and verify_server to use it
		# auction_list = [{'TITLE': 'test', 'AUCTION_ID': 1},{'TITLE': 'test2', 'AUCTION_ID': 2}]

		# Build Titles Of Auctions To Be printed
		for auction in auction_list:
			title = colorize('[ENGLISH]	', 'blue') if auction["TYPE"] == 1 else colorize('[BLIND]	', 'pink')
			if auction["STATUS"]:
				title += colorize('[OPEN] ', 'green')
			elif auction["CLAIMED"]:
				title += colorize('[CLOSED] ', 'red')
			else:
				title += colorize('[WAITING FOR CLAIM] ', 'pink')
			auctions.append({title + auction["TITLE"] : (list_auction, (auction["AUCTION_ID"],)) })
		auctions.append({ "Refresh" : (list_auction, ()) })
		auctions.append({ "Exit" : None })

		# Print the menu
		print_menu(auctions)

	# In case of getting a particular auction
	else:
		# Printing Auction Information
		auction = server_answer['MESSAGE']['AUCTION']
		# test subject comment line above and verify_server to use it
		#auction = {"AUCTION_ID" : 1, "TITLE" : "Tomatoes", "DESCRIPTION" : "Tomatoes from my beautiful farm",
		#				"TYPE" : 1, "SUBTYPE" : 2, "WHO_HIDES": 1, "ENDING_TIMESTAMP" : 1548979200, "BIDS" : [] }

		# Translating Type/Subtype/WhoHide in order for user to understand
		auction["TYPE"] = "ENGLISH" if auction["TYPE"] == 1 else "BLIND"
		auction["SUBTYPE"] = "PUBLIC IDENTITY" if auction["SUBTYPE"] == 1 else "HIDDEN IDENTITY"

		# Building Infomation to print
		auction_info = []
		auction_info.append( colorize('TITLE:		', 'pink') + auction["TITLE"])
		auction_info.append( colorize('DESCRIPTION:	', 'pink') + auction["DESCRIPTION"] )
		auction_info.append( colorize('TYPE:		', 'pink') + auction["TYPE"] )
		auction_info.append( colorize('SUBTYPE:	', 'pink') + auction["SUBTYPE"] )
		auction_info.append( colorize('SEED:		', 'pink') + auction["SEED"] )
		auction_info.append( colorize('BIDS:	', 'pink') )

		auction_info.append( colorize("============================", 'green') )

		for bid in auction["BIDS"]:
			if auction["SUBTYPE"] == "HIDDEN IDENTITY":
				if not auction["STATUS"]:
					identity = decrypt(fromBase64(bid["KEY"]), fromBase64(bid["IDENTITY"])).decode()
					auction_info.append( colorize("IDENTITY:	" + identity + "  [" + bid["IDENTITY"] + "]", 'blue') )
				else:
					auction_info.append( colorize("IDENTITY:	" + bid["IDENTITY"], 'blue') )
			else:
				auction_info.append( colorize("IDENTITY:	" + fromBase64(bid["IDENTITY"]).decode(), 'blue') )

			if auction["TYPE"] == "ENGLISH":
				auction_info.append( colorize("VALUE:		" + fromBase64(bid["VALUE"]).decode() + "€", 'blue') )
			else:
				if not auction["STATUS"]:
					value = decrypt(fromBase64(bid["KEY"]), fromBase64(bid["VALUE"])).decode()
					auction_info.append( colorize("VALUE:		" + value + "€  [" + bid["VALUE"] + "]", 'blue') )
				else:
					auction_info.append( colorize("VALUE:		" + bid["VALUE"], 'blue') )

			if not auction["STATUS"]:
				auction_info.append( colorize("KEY:		" + bid["KEY"], 'blue') )
			auction_info.append( colorize("PREVIOUS HASH:	" + bid["PREV_HASH"], 'blue') )
			auction_info.append( colorize("============================", 'green') )

		if len(auction["BIDS"]):
			are_bids_valid = validate_blockchain(auction["BIDS"], auction["SEED"])
			if are_bids_valid:
				auction_info.append( colorize("BLOCKCHAIN:	", 'pink') + "VALID")
			else:
				auction_info.append( colorize("BLOCKCHAIN:	", 'pink') + colorize("INVALID (contact admin please)", 'red'))

		auction_info.append( colorize('ENDS IN:        ', 'pink') + colorize('AUCTION ENDED', 'red') )
		auction_info.append( "======================================================" )


		# Bulding Menu With Options For The Client
		menu = []
		if(auction["STATUS"]):
			menu.append({"Make Offer" : (make_bid, (auction["AUCTION_ID"], \
						auction["TYPE"] == "ENGLISH", auction["SUBTYPE"] == "HIDDEN IDENTITY"))})
			menu.append({"Terminate Auction (you must be the owner)" : (terminate_auction, auction_id) })
			menu.append({ "Refresh" : (list_auction, (auction["AUCTION_ID"], )) })
		else:
			auction["ENDING_TIMESTAMP"] = -1
			if(not auction["CLAIMED"]):
				menu.append({"Reclaim Prize" : (reclaim, (auction["AUCTION_ID"], auction["TYPE"] == "ENGLISH"))})
				menu.append({ "Refresh" : (list_auction, (auction["AUCTION_ID"], )) })
		menu.append({ "Exit" : None })

		# Print Menu
		print_menu(menu, auction_info, auction["ENDING_TIMESTAMP"])

def make_bid(arg):
	'''
		Creates new bid (offer) to a given auction (auction_id)

		Steps:
			1 - If there are values to be encrypted by client: encrypt them with generated key
				If there are values to be encrypted by manager: encrypt them with manager public key
			2 - Send Bid To Repository
			3 - Save Receipt

	'''

	# Reading arguments
	auction_id = arg[0]
	is_english = arg[1]
	hidden_identity = arg[2]

	# Scanning user CartaoDeCidadao
	logging.info("Reading User's Cartao De Cidadao")
	print( colorize( "Reading Citizen Card, please wait...", 'pink' ) )
	cc.scan()
	clean(lines = 1)

	# Init values for the bid (value to offer and identity of user)
	value = 0
	identity = (cc.get_identity()[0] + ' - ' + cc.get_identity()[1]).encode("UTF-8")
	certificate = cc.get_certificate_raw()

	# Ask user for value to offer
	while True:
		try:
			value = int(input("Value to offer (EUR) : "))
		except ValueError:
			print( colorize('Limit must be a number!', 'red') )
			clean()
			continue
		else:
			if value >= 0:
				confirm = input("Are you sure? Bids are irreversible [y/N]: ").upper()
				if confirm.startswith("Y"):
					clean(True)
					break
				clean()
				continue
			else:
				print( colorize('Please pick a positive number.', 'red') )
				clean()

	value = str(value).encode("UTF-8")
	# Preparing data
	print( colorize( "Preparing data, please wait...", 'pink' ) )
	logging.info("Auction Requires to Encrypt Values, Encrypting...")

	# Hiding needed values
	cipher_key = os.urandom(32)
	# Import his certificate to encrypt cipher_key
	manager_cert = CertManager.get_cert_by_name('manager.crt')
	cm = CertManager(manager_cert)
	hidden_cipher_key = cm.encrypt(cipher_key)

	# Need to hide identity?
	if (hidden_identity):
		identity = encrypt(cipher_key, identity)
		certificate = encrypt(cipher_key, certificate)
	# Need to hide value?
	if (not is_english):
		value = encrypt(cipher_key, value)

	nonce = os.urandom(64)
	# Ask for CryptoPuzzle
	crypto_puzzle_request = {
								"ACTION" : "CRYPTOPUZZLE",
								"IDENTITY" : toBase64(identity),
								"AUCTION_ID" : auction_id,
								"NONCE" : toBase64(nonce)
							}

	# Send CryptoPuzzle Request
	logging.info("Sending CryptoPuzzle request to Repository")
	sock_repository.send( json.dumps(crypto_puzzle_request).encode("UTF-8") )
	# Waiting for server response
	'''
		DESCRIPTION:
			This message is to request a cryptopuzzle to the repository,
			not much to add about it, it gives a identity to be used on the
			cryptopuzzle generation (function create_puzzle in CryptoPuzzle package)

		SENT MESSAGE:
		{
			"ACTION" : "CRYPTOPUZZLE",
			"IDENTITY" : _____,
			"AUCTION_ID" : ________,
			"NONCE" : _______
		}
		EXPECTED ANSWER:
		{
			"ACTION" : "CRYPTOPUZZLE_REPLY",
			"MESSAGE" : {
							"PUZZLE" : ____,			# These are the values that create_puzzle will return
							"STARTS_WITH" : ____,
							"ENDS_WITH" : ____,
							"NONCE" : _____
						}
			"SIGNATURE" :  _____  (OF MESSAGE),
			"CERTIFICATE" : _____
		}
	'''
	server_answer = wait_for_answer(sock_repository, "CRYPTOPUZZLE_REPLY")
	if not server_answer: return
	logging.info("Received CryptoPuzzle: " + json.dumps(server_answer))

	# Verify server certificate, verify signature message and challenge
	message = server_answer['MESSAGE']
	logging.info("Verifying certificate and server signature of message")

	if  toBase64(nonce) != message["NONCE"] or \
		 not verify_server( server_answer['CERTIFICATE'], json.dumps(message).encode('UTF-8'), server_answer['SIGNATURE'] ):
		logging.warning("Server Verification Failed")
		print( colorize('Server Validation Failed!', 'red') )
		input("Press any key to continue...")
		return

	logging.info("Solving CryptoPuzzle...")
	solution = CryptoPuzzle().solve_puzzle(message["PUZZLE"], identity, \
				fromBase64(message["STARTS_WITH"]) , fromBase64(message["ENDS_WITH"]))

	bid = 	{
				"AUCTION" 		: auction_id,
				"VALUE"			: toBase64(value),
				"IDENTITY"		: toBase64(identity),
				"SOLUTION"		: toBase64(solution),
			}

	logging.info("Signing Bid...")
	signed_bid = cc.sign( json.dumps(bid).encode('UTF-8') )
	message = 	{
					"ACTION" : "OFFER",
					"MESSAGE" : bid,
					"SIGNATURE" : toBase64(signed_bid)
				}

	# Key encrypted with manager public_key so he can read identity/value
	message["MANAGER_SECRET"] = toBase64(hidden_cipher_key)
	message["CERTIFICATE"] = toBase64(certificate)

	# Send Offer
	logging.info("Sending Bid To Repository")
	sock_repository.send( json.dumps(message).encode("UTF-8") )
	'''
		DESCRIPTION:
			Client solved the puzzle so it will now return the solution together
			with his offer. VALUE and CERTIFICATE may be encrypted depending of the
			properties of the auction. The key used in this encryption is given in
			MANAGER_SECRET in case the auction is set as "SERVER/MANAGER hides".
			Obviously, the key in manager secret is encrypted with manager's public key
			so that the repository cant know it.
			What to do after?
				1 - The repository will check the cryptopuzzle solution
				2 - In case of valid, send the bid to manager for validation
				3 - In case "MANAGER_SECRET" is available, use it decrypt "IDENTITY"/"VALUE" and validate bid and signature.
				4 - If valid, sign "MESSAGE" and "SIGNATURE" and send it to repository
				5 - Repository now stores the bid and signs on top of manager signature
				6 - Send the result to the client, as receipt.

		SENT MESSAGE:
		{
			"ACTION" : "OFFER",
			"MESSAGE" : {
							"AUCTION" 		: ______,
							"VALUE"			: ______, (may be encrypted)
							"CERTIFICATE"	: ______, (may be encrypted)
							"SOLUTION"		: ______,
						},
			"SIGNATURE" : ________,
			"MANAGER_SECRET" : ______ (Optional, present if manager is going to hide something)
		}
		EXPECTED ANSWER:
		{
			"ACTION": "RECEIPT",
			"STATE" : ________,
			"RECEIPT": ________
		}
	'''
	# Waiting for server response
	server_answer = wait_for_answer(sock_repository, "RECEIPT")
	if not server_answer: return
	logging.info("Received Answer From Server: " + json.dumps(server_answer))

	logging.info("Validating and Saving Receipt...")

	if (server_answer["STATE"] == "OK"):
		rm = ReceiptManager(cc)
		if ( rm.validate_receipt(server_answer["RECEIPT"]) ):
			clean(lines=1)
			server_answer["RECEIPT"]["KEY"] = toBase64(cipher_key)
			print( colorize( "Receipt received, please type your password to save it.", 'pink' ) )
			rm.save_receipt(str(auction_id), json.dumps(server_answer["RECEIPT"]).encode("UTF-8"), server_answer["RECEIPT"]["ONION_2"]["PREV_HASH"])
			clean(lines=1)
			input( colorize( "Bid successfully set. Press any key to continue...", 'blue' ) )
		else:
			logging.error("Received an invalid receipt!")
			clean(lines=1)
			input(colorize( "Invalid Receipt Received, press any key to continue...", 'red' ))
	elif (server_answer["STATE"] == "NOT OK"):
		clean(lines=1)
		logging.info("Offer Failed : " + server_answer["ERROR"] )
		print( colorize("ERROR: " + server_answer["ERROR"], 'red') )
		input("Press any key to continue...")
	else:
		clean(lines=1)
		logging.info("Offer Failed With Unexpected Error ")
		print( colorize("Something really weird happen, please fill a bug report.", 'red') )
		input("Press any key to continue...")

	return list_auction((auction_id,))

def terminate_auction(auction_id):
	'''
		Terminate an open auction
	'''
	# Are you sure?
	answer = input("Are you sure you want to terminate this auction? [y/N]: ")
	if(not answer.upper().startswith("Y")):
		return
	clean(lines = 1)

	# Scanning user CartaoDeCidadao
	logging.info("Reading User's Cartao De Cidadao")
	print( colorize( "Reading Citizen Card, please wait...", 'pink' ) )
	cc.scan()
	clean(lines = 1)

	# Establish connection with server
	print( colorize( "Establishing connection with server, please wait...", 'pink' ) )
	logging.info("Trying to establishing connection with server")

	# Sending challenge to the server
	challenge = os.urandom(64)
	connection = {"ACTION": "CHALLENGE", "CHALLENGE":  toBase64(challenge)  ,\
	 			  "CERTIFICATE": toBase64(cc.get_certificate_raw()) }
	sock_manager.send( json.dumps(connection).encode("UTF-8") )
	logging.info("Sent Challenge To Server: " + json.dumps(connection))

	# Wait for Challenge Response
	server_answer = wait_for_answer(sock_manager , "CHALLENGE_REPLY")
	if not server_answer: return
	logging.info("Received Challenge Response: " + json.dumps(server_answer))

	# Verify server certificate, verify signature of challenge and decode NONCE
	logging.info("Verifying certificate and server signature of challenge")
	if not verify_server( server_answer['CERTIFICATE'], challenge, server_answer['CHALLENGE_RESPONSE'] ):
		logging.warning("Server Verification Failed")
		print( colorize('Server Validation Failed!', 'red') )
		input("Press any key to continue...")
		return

	terminate_inner = 	{
					"AUCTION_ID": auction_id,
					"NONCE": server_answer["NONCE"]
						}

	# Signing and creating OUTTER layer of JSON message
	logging.info("Signing Message To Send Server")
	signed_message = cc.sign( json.dumps(terminate_inner).encode('UTF-8') )

	terminate_outter = 	{
					"ACTION" : "TERMINATE",
					"MESSAGE": terminate_inner,
					"SIGNATURE": toBase64(signed_message)
						}

	# Sending Terminate Auction Request For Auction Manager
	logging.info("Sending Request To Server:" + json.dumps(terminate_outter))
	sock_manager.send( json.dumps(terminate_outter).encode("UTF-8") )

	clean(lines = 1)
	# Wait for Server Response
	logging.info("Waiting for server response")
	print( colorize( "Terminating Auction, please wait...", 'pink' ) )
	server_answer = wait_for_answer(sock_manager, "TERMINATE_REPLY")
	if not server_answer: return
	logging.info("Received Server Response: " + json.dumps(server_answer))

	if (server_answer["STATE"] == "OK"):
		clean(lines=1)
		logging.info("Auction Termination Was Successful")
		print( colorize("Auction successfully terminated!", 'pink') )
		input("Press any key to continue...")
	elif (server_answer["STATE"] == "NOT OK"):
		clean(lines=1)
		logging.info("Auction Termination Failed : " + server_answer["ERROR"] )
		print( colorize("ERROR: " + server_answer["ERROR"], 'red') )
		input("Press any key to continue...")
	else:
		clean(lines=1)
		logging.info("Auction Termination Failed With Unexpected Error ")
		print( colorize("Something really weird happen, please fill a bug report.", 'red') )
		input("Press any key to continue...")

def my_bids(*arg):
	'''
		Browse Participated Auctions
	'''

	# Scanning user CartaoDeCidadao
	logging.info("Reading User's Cartao De Cidadao")
	print( colorize( "Reading Citizen Card, please wait...", 'pink' ) )
	cc.scan()
	clean(lines = 1)

	logging.info("Getting Participated Auctions")
	print( colorize( "Getting Participated Auctions", 'pink' ) )
	rm = ReceiptManager(cc)
	participated_auctions = rm.get_participated_auctions()

	if participated_auctions == []:
		clean(lines = 1)
		input("You have no history of bids yet. Press any key to continue...")
		return

	auction_list = list_auction((participated_auctions, True))
	auctions = []
	# Build Titles Of Auctions To Be printed
	for auction in auction_list:
		title = colorize('[ENGLISH] ', 'blue') if auction["TYPE"] == 1 else colorize('[BLIND] ', 'pink')
		title += auction["TITLE"]
		bids = rm.get_receipt_value(str(auction["AUCTION_ID"]), auction["TYPE"] == 2)
		title += colorize('\n	Your BIDS:	' + bids[0][0] + '€	Previous Hash:'+ bids[0][1] +'\n', 'red')
		for bid in bids[1:]:
			title += colorize('			' + bid[0] + '€	Previous Hash:'+ bid[1] +'\n', 'red')
		auctions.append({title: (list_auction, (auction["AUCTION_ID"],)) })
	auctions.append({ "Exit" : None })

	# Print the menu
	print_menu(auctions)


def print_menu(menu, info_to_print = None, timestamp = None):
	'''
		Print menu to the user
	'''
	while True:
		os.system('clear')													# Clear the terminal
		ascii = open('src/common/ascii', 'r')								# Reading the sick ascii art
		print( colorize(ascii.read(), 'pink') )								# Printing the ascii art as pink
		ascii.close()
		print('\n')

		# Print info if there is any
		if info_to_print:
			for info in info_to_print:
				print(info)

		# Printing the menu together with the index
		for item in menu:
			print( str(menu.index(item) + 1) + " - " + list(item.keys())[0] )

		# Print Count Down For Auction
		if info_to_print and timestamp != -1:
			p = Process(target=print_timer, args=(timestamp,6))
			p.start()
			choice = input(">> ")
			p.terminate()
		else:
			choice = input(">> ")

		try:																# Reading the choice
			if int(choice) <= 0 : raise ValueError
			if list(menu[int(choice) - 1].values())[0] == None: return
			list(menu[int(choice) - 1].values())[0][0](list(menu[int(choice) - 1].values())[0][1])
			if list(menu[int(choice) - 1].keys())[0] == "Refresh": return
			if info_to_print: return
		except (ValueError, IndexError):
			pass

# Default Menu to be printed to the user
menu = [
    { "Create new auction": (create_new_auction, None) },
    { "List Auctions": (list_auction, () ) },
	{ "Participated Auctions": (my_bids, None)},
	{ "Exit" : None }
]

def main():
	print_menu(menu)


if __name__ == "__main__":
    main()
