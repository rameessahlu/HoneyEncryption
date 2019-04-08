import hashlib, uuid
import rsa
import random, sys, os
import pprint

class UserManagementModule:
	user_name = 'ramees'
	pass_word = '26111994'
	
	def _auth(self, un, pw):
		if un in self.user_name and pw in self.pass_word:
			return True
		else:
			return False

class LicenseGenerator:
	licenseToSeeds = {}   # dictionary
	seedsToAuthKey = {}    # dictionary
	cipher = 0
	trueSeed = 0
	def __init__(self):
		self.trueSeed = random.randint(10, 27)    # Random seed value
		licenseKey = {
			"ngns" : "nogutsnostory",
			"dbpb" : "dreambigpraybigger",
			"lnsu" : "leavenostoneunturned",
			"mlimm" : "mylifeismymessage"
		} #1:3 ratio
		accessKey = ['access0', 'access8', 'access5', 'access25']
		
		true_license = licenseKey['ngns']
		true_access_key = accessKey[2]
		
		self.licenseToSeeds['nogutsnostory'] = self.trueSeed
		self.seedsToAuthKey[self.trueSeed] = accessKey[2]

		self.licenseToSeeds['dreambigpraybigger'] = self.trueSeed + 1
		self.seedsToAuthKey[self.trueSeed + 1] = accessKey[0]

		self.licenseToSeeds['leavenostoneunturned'] = self.trueSeed + 2
		self.seedsToAuthKey[self.trueSeed + 2] = accessKey[1]

		self.licenseToSeeds['mylifeismymessage'] = self.trueSeed + 6
		self.seedsToAuthKey[self.trueSeed + 6] = accessKey[3]

		print("The true license is " + true_license
			+ ", True seed value is " + str(self.trueSeed)
			+ ", and the true access key is " + true_access_key
			+ "\n=====================================")
		
		# ENCRYPTION: c = sk XOR sm
		self.cipher = int(self.licenseToSeeds['nogutsnostory']) ^ self.trueSeed
		print(self.cipher)
		# Shuffle the licenses and display them on the screen to begin the process
		licenses = list(self.licenseToSeeds.keys())
		random.shuffle(licenses)                   # Shuffle the licenses
		print('The sweet words: ' + str(licenses))                           # Display results

class OfflineValidation:
	def _validation(self, userName, userPass ,license, pubkey):
		licenseKey = {
			"ngns" : "nogutsnostory",
			"dbpb" : "dreambigpraybigger",
			"lnsu" : "leavenostoneunturned",
			"mlimm" : "mylifeismymessage"
		}
		if license in licenseKey.values():
			print('The software product is offline activated!')
		else:
			print('Offline activation failed!')
			sys.exit(0)
		salt = userPass #uuid.uuid4().hex
		hashed_license = hashlib.sha256(('%s%s' % (license, salt)).encode('utf-8')).hexdigest()
		
		xored_value = self.xor(('%s:%s' % (userName, license)), hashed_license)
		
		concatnated_value = ('%s:%s' % (xored_value, hashed_license))
		
		#The private key in PEM format
		#The public key in PEM Format
		
		cipher_t = self.encrypt_input(concatnated_value.encode('utf8'), pubkey)
		return cipher_t
		#if plain.decode('utf8') == hashed_license:
		#	print(plain.decode('utf8'))

	def xor(self, str1, str2):
		return ''.join(chr(ord(a)^ord(b)) for a,b in zip(str1,str2))

	#Our Encryption Function
	def encrypt_input(self, blob, pub_key):
		cipher = rsa.encrypt(blob, pub_key)
		return cipher

class OnlineValidation:
	def __init__(self, licgen, enteredLicense, privkey, cipher_text, hc):
		plain = self.decrypt_input(cipher_text, privkey)
		plain = plain.decode('utf-8')
		hash_v = plain.split(':')[1]
		xored_v = plain.split(':')[0]
		un_and_lic = self.xor(xored_v, hash_v)
		hc.honey_check(un_and_lic.split(':')[0], un_and_lic.split(':')[1])
	def decrypt_input(self, blob, privkey):
		cipher = rsa.decrypt(blob, privkey)
		return cipher

	def xor(self, str1, str2):
		return ''.join(chr(ord(a)^ord(b)) for a,b in zip(str1,str2))

class HoneyChecker:
	licgen = None
	entered_lic = ''
	def __init__(self, lic_gen, license):
		self.licgen = lic_gen
		self.entered_lic = license

	def honey_check(self, un, pw):
		try:
			keySeed = self.licgen.licenseToSeeds[self.entered_lic]
			# DECRYPTION: m = sk XOR c
			m = keySeed ^ self.licgen.cipher        # ^ == XOR

			if m != self.licgen.trueSeed:           # Honey checker
				print("Intruder! SOUNDING ALARM!")  # If seeds don’t match, this is an intruder

			# Check seeds
			print(self.licgen.seedsToAuthKey[m])
		except KeyError:
			print("License not found. ")

if __name__ == '__main__':
	umm = UserManagementModule()
	offv = OfflineValidation()
	
	print('###########License Generation###########')
	lg = LicenseGenerator()
	
	#Generate a public/ private key pair using 4096 bits key length (512 bytes)
	(rsa_pubkey, rsa_privkey) = rsa.newkeys(1024, poolsize=8)
	
	print('###########Offline Activation###########')
	print('Please enter the username, password and license key: ')
	username = input('Username: ')
	password = input('Password: ')
	license = input('License Key: ')
	
	#offline activation
	print('Would you like to do an offline activation: ')
	decision = input('Type Y or N: ')
	while decision != 'Y' and decision != 'N':
		decision = input('Type Y or N: ')
	if decision == 'N':
		print('App is closing.')
		sys.exit(0)
	print('Proceeding with Offline Activation.')
	cipher_t = offv._validation(username, password, license, rsa_pubkey)
	
	print('###########Online Activation###########')
	if(umm._auth(username, password)):
		print('User "{}" successfully logged in.'.format(username))
	else:
		print('Online Activation Procedure failed! Incorrect username and password entered.')
	hc = HoneyChecker(lg, license)
	onv = OnlineValidation(lg, license, rsa_privkey, cipher_t, hc)