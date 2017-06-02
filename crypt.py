# Copyright (C) 2016-2017 luckyhacker.com
from hashlib import sha256
import time, sys, random, math, os, re, shutil

'''
Simple XOR operation encrypting
'''
class XOR:

	def __init__(self, key, *job):
		self.key = key
		if job:
			self.pb = ProgressBar(job[0])

	def insert_data(self, data):
		self.data = data
		self.key_multiplier = int(len(self.data) / len(self.key))
		if self.key_multiplier < 1:
			self.key_multiplier = 1
		self.key = self.key * self.key_multiplier
		while len(self.key) < len(self.data):
			self.key += self.key
		return self._encrypt()

	def _encrypt(self):
		'''
		Encrypt function can do the encrypting and decrypting
		with XOR operation.
		'''
		try:
			self.pb.display()
		except:
			pass
		return "".join(list(map(lambda x, y: chr(ord(x) ^ ord(y)), self.data, self.key)))


'''
ShuffleXOR creates blocks whose size and quantity depends on data length,
then it shuffles them based on key and uses XOR operation in XOR class
to encrypt every single character. Usage of UI is optional (off by default).
'''
class ShuffleXOR:

	def __init__(self, data, key, UI=False):
		# Variables
		self.UI = UI
		self.blocks = []
		self.keylist = [] # Key chars as decimals
		self.keyvalues = [] # Values that will used to shuffle blocks
		self.key = key
		self.data = data

	def encrypt(self):
		if self.UI == True:
			print("Encrypting")

		self._gen_salt()
		self._get_keyhash(self.salt)
		self._get_blocks(self.data)
		self._get_keyvalues()

		'''
		XOR whole data with original key and keyhash to ensure that no valid
		password is shown in encrypted file. Also XOR certain blocks with
		salt to strengthen security.
		(Looking for more efficient solution)
		'''

		if self.UI == True:
			step_one_encrypt = XOR(self.key, len(self.blocks)*2)
			step_two_encrypt = XOR(self.keyhash)
			step_two_encrypt.pb = step_one_encrypt.pb
		else:
			step_one_encrypt = XOR(self.key)
			step_two_encrypt = XOR(self.keyhash)

		self.blocks = list(map(step_one_encrypt.insert_data, self.blocks))
		self._partial_encrypt()
		return self.salt + "".join(list(map(step_two_encrypt.insert_data, self.blocks)))

	def decrypt(self):
		if self.UI == True:
			print("Decrypting")

		self._get_salt()
		self._get_keyhash(self.salt)
		self._get_blocks(self.data)
		self._get_keyvalues()

		if self.UI == True:
			step_one_decrypt = XOR(self.key, len(self.blocks)*2)
			step_two_decrypt = XOR(self.keyhash)
			step_two_decrypt.pb = step_one_decrypt.pb
		else:
			step_one_decrypt = XOR(self.key)
			step_two_decrypt = XOR(self.keyhash)

		self.blocks = list(map(step_one_decrypt.insert_data, self.blocks))
		self._partial_decrypt()
		return "".join(list(map(step_two_decrypt.insert_data, self.blocks)))

	def _partial_encrypt(self): # Encrypt certain blocks with salt while shuffling
		partial_encrypter = XOR(self.saltkey)
		amount_blocks_to_encrypt = int(math.sqrt(self.block_amount))

		for i in range(amount_blocks_to_encrypt):
			encrypt_index = (len(self.blocks) % ((i+1) * amount_blocks_to_encrypt)-1)
			self.blocks[encrypt_index] = partial_encrypter.insert_data(self.blocks[encrypt_index])
			self._shuffle_blocks()


	def _partial_decrypt(self): # Decrypt certain blocks with salt while shuffling
		decrypt_indexes = []
		partial_decrypter = XOR(self.saltkey)
		amount_blocks_to_decrypt = int(math.sqrt(self.block_amount))
		for i in range(amount_blocks_to_decrypt): # We need to walk all same indexes backwards that are used in partialencrypter
			decrypt_indexes.append((len(self.blocks) % ((i+1) * amount_blocks_to_decrypt)-1))

		for i in range(amount_blocks_to_decrypt):
			self._sort_blocks()
			self.blocks[decrypt_indexes[-(i+1)]] = partial_decrypter.insert_data(self.blocks[decrypt_indexes[-(i+1)]])

	def _get_keyhash(self, salt): # Getting KeyHash from key and salt combination
		self.saltkey = self.key + salt
		self.keyhash = sha256(self.saltkey.encode("utf-8")).hexdigest()

	def _get_salt(self): # Getting salt from data when decrypting
		self.salt = self.data[:16]
		self.data = self.data[16:]

	def _gen_salt(self): # Generating salt when encrypting
		self.salt = "".join(map(lambda x: chr(random.randint(1, 255)), range(16)))

	def _sort_blocks(self): # Sorting blocks back to original order.
		sorted_data = [None] * len(self.keyvalues)
		dest_key_values = self.keyvalues[:]
		self.keyvalues.sort()
		self.blocks = list(zip(self.keyvalues, self.blocks))
		self.blocks.sort(key=lambda x: dest_key_values.index(x[0]))
		self.blocks = list(map(lambda x: x[1], self.blocks))
		self.keyvalues = dest_key_values

	def _shuffle_blocks(self): # Shuffle blocks based on self.Keyvalues
		for i in range(len(self.keyvalues)):
			self.blocks[i] = (self.keyvalues[i], self.blocks[i])
		self.blocks.sort(key=lambda x: x[0])

		for i in range(len(self.blocks)):
			self.blocks[i] = self.blocks[i][1]

	def _get_blocks(self, data): # Form blocks from data
		self.block_size = math.ceil(math.sqrt(len(data)))
		self.block_amount = math.ceil(len(data) / self.block_size)
		for i in range(int(self.block_amount)):
			self.blocks.append(data[i*int(self.block_size):(i+1)*int(self.block_size)])
		del self.data

	def _get_keyvalues(self): # Get self.Keyvalues based on amount of blocks
		for i in range(len(self.blocks)):
			self.keylist.append(ord(self.keyhash[(len(self.keyhash) % (i+1))-1]))

		j = 0
		base_value = 1
		while len(self.keyvalues) < len(self.blocks):
			if j < len(self.keylist):
				value = self.keylist[j]
			if value not in self.keyvalues: # Use different keyvalues!
				self.keyvalues.append(value)
			else:
				'''
				Get value from logarithm last decimals
				'''
				base_value += 1
				value += int(str(math.log(base_value)).replace(".", "")[-len(str(j)):])
			j += 1

		'''
		This is needed if padding is not used in the end of data!!
		(Last block needs to stay last) Maybe use padding in the future?
		'''
		m = max(self.keyvalues)
		self.keyvalues.remove(m)
		self.keyvalues.append(m)


'''
Used to encrypt and decrypt files. Path to file and password to encrypt with
are required as parameters.
'''
class XORFile:

	def __init__(self, srcfp, key):
		self.mega_byte = 1048576
		self.srcfp = srcfp
		self.key = key
		self.srcf = open(self.srcfp, "rb")
		self._get_encoding()

	def _get_encoding(self): # Detect file encoding
		with open(self.srcfp, "rb") as f:
			data = f.read(1024)

		try:
			data = str(data, "utf-8")
			self.encoding = "utf-8"
		except:
			data = str(data, "Latin-1")
			self.encoding = "Latin-1"

	def encrypt(self, dstfp): # Encrypt data using ShuffleXOR
		self.dstf = open(dstfp, "wb")
		while True:
			data = str(self.srcf.read(self.mega_byte), self.encoding)
			if data == "": break
			self.dstf.write(bytes(ShuffleXOR(data, self.key).encrypt(), self.encoding))

	def decrypt(self, dstfp): # Decrypt data using ShuffleXOR
		self.dstf = open(dstfp, "wb")
		while True:
			data = str(self.srcf.read(self.mega_byte + 16), self.encoding)
			if data == "": break
			self.dstf.write(bytes(ShuffleXOR(data, self.key).decrypt(), self.encoding))


'''
Used to encrypt and decrypt folders. Path to folder, destination path and key are
required as parameters.
'''
class XORFolder:

	def __init__(self, srcfp, key, UI=False):
		self.mega_byte = 1048576
		self.key = key
		self.UI = UI
		# Path variables
		self.root_folder = ""
		self.srcfp = srcfp
		self.file_paths = []
		self.folder_paths = []

		# Metadata related variables
		self.meta_begin_tag = "[METABEGIN]"
		self.meta_end_tag = "[METAEND]"
		self.meta_data = ""

		self.folders_begin_tag = "[FOLDERSBEGIN]"
		self.folders_end_tag = "[FOLDERSEND]"
		self.folders_sep_tag = "[FOLDERSSEP]"

		self.filepath_begin_tag = "[FILEPATHBEGIN]"
		self.filepath_end_tag = "[FILEPATHEND]"
		self.filepath_sep_tag = "[FILEPATHSEP]"

		self.file_begin_tag = "[FILEBEGIN]"
		self.file_end_tag = "[FILEEND]"

	def encrypt(self, dstfp):
		self.root_folder = ".XORFoldertmp" + os.path.sep
		self.dstfp = dstfp
		self._get_paths()
		self._make_folders()
		self._form_meta_data()

		'''
		XOR every file seperately to temp path
		'''
		pb = ProgressBar(len(self.file_paths))
		for fp in self.file_paths:
			if self.UI == True:
				pb.display()
			XORFile(fp, self.key).encrypt(self.root_folder + fp)

		self._files_to_file()
		shutil.rmtree(self.root_folder, ignore_errors=True)

	def decrypt(self, dstfp):
		self.root_folder = ".XORFoldertmp" + os.path.sep
		self._get_meta_data()
		self._make_folders()

		self._file_to_files()

		self.tmp_folder = self.root_folder
		self.root_folder = dstfp + os.path.sep
		self._make_folders()

		pb = ProgressBar(len(self.file_paths))
		for fp in self.file_paths:
			if self.UI == True:
				pb.display()
			if fp != "":
				XORFile(self.tmp_folder + fp, self.key).decrypt(dstfp + os.path.sep + fp)

		shutil.rmtree(self.tmp_folder, ignore_errors=True)

	def _files_to_file(self): # Move files from temp path to one encrypted file
		with open(self.dstfp, "wb+") as tf: # Format destination file
			tf.write(bytes(self.meta_begin_tag + ShuffleXOR(self.meta_data, self.key).encrypt() + self.meta_end_tag, "Latin-1"))

		with open(self.dstfp, "ab") as f:
			for fp in self.file_paths:
				with open(self.root_folder + fp, "rb") as sf:
					data = sf.read()
					f.write(bytes(self.file_begin_tag, "Latin-1") + data + bytes(self.file_end_tag, "Latin-1"))

	def _file_to_files(self): # Extract files from one encrypted file
		with open(self.srcfp, "rb") as f:
			data = re.findall(r"\[FILEBEGIN\](.*?)\[FILEEND\]", str(f.read(), "Latin-1"), re.DOTALL)
			for i in range(len(self.file_paths)):
				if self.file_paths[i] != "":
					with open(self.root_folder + self.file_paths[i], "wb+") as df:
						df.write(bytes(data[i], "Latin-1"))

	def _get_paths(self): # Get path of folders and files (Encrypting)
		for path, dirs, files in os.walk(self.srcfp):
			self.folder_paths.append(path)
			for f in files:
				self.file_paths.append(path + os.path.sep + f)

	def _make_folders(self): # Make all folders to destination path
		for path in self.folder_paths:
			try:
				os.makedirs(self.root_folder + path)
			except FileExistsError:
				pass

	def _form_meta_data(self): # Form meta data for folders and file paths
		self.meta_data += self.folders_begin_tag
		for folder in self.folder_paths:
			self.meta_data += folder + self.folders_sep_tag
		self.meta_data += self.folders_end_tag

		self.meta_data += self.filepath_begin_tag
		for filename in self.file_paths:
			self.meta_data += filename + self.filepath_sep_tag
		self.meta_data += self.filepath_end_tag

	def _get_meta_data(self): # Get metadata from encrypted file (Decrypting)
		with open(self.srcfp, "rb") as f:
			data = str(f.read(self.mega_byte), "Latin-1")
			while self.meta_begin_tag not in data and self.meta_end_tag not in data:
				data += str(f.read(self.mega_byte), "Latin-1")
		self.meta_data = ShuffleXOR(re.findall(r"\[METABEGIN\](.*?)\[METAEND\]", data, re.DOTALL)[0], self.key).decrypt()
		self.folder_paths = re.findall(r"\[FOLDERSBEGIN\](.*?)\[FOLDERSEND\]", self.meta_data, re.DOTALL)[0].split("[FOLDERSSEP]")
		self.file_paths = re.findall(r"\[FILEPATHBEGIN\](.*?)\[FILEPATHEND\]", self.meta_data, re.DOTALL)[0].split("[FILEPATHSEP]")

'''
Trying to create simple and fast hash function
'''
class LHash:

	def hash(self, data):
		self.hash_int = sum(list(map(lambda x: ord(x), data)))
		while len(str(self.hash_int)) < 64:
			self.hash_int = self.hash_int**2
		return str(self.hash_int)[:64]


class ProgressBar:

	def __init__(self, job):
		self.progress = 0
		self.job = job
		self.start_time = time.time()

	def _progress(self):
		total_time = int(time.time() - self.start_time)
		self.eta = "0"
		self.elapsed = "0"
		self.p = float(self.progress) / float(self.job) * 100
		self.bar = "[" + "="*int(self.p/float(10)*2) + " "*(20-int(self.p/float(10)*2)) + "]"
		if self.job == self.progress+1:
			self.bar = "[" + "="*20 + "]"
			self.p = 100.0
		if self.p > 0:
			seconds_eta =  total_time * (100 / self.p) - total_time
			self.eta = str(int(seconds_eta)) + "s"
			if seconds_eta > 60:
				minutes_eta = seconds_eta / 60
				self.eta = str(int(minutes_eta)) + "m " + str(int(seconds_eta % 60)) + "s"
				if minutes_eta > 60:
					hours_eta = minutes_eta / 60
					self.eta = str(int(hours_eta)) + "h " + str(int(minutes_eta % 60)) + "m " + str(int(seconds_eta % 60)) + "s"
		if self.p > 0:
			self.elapsed = str(total_time) + "s"
			if total_time > 60:
				minutes_elapsed = total_time / 60
				self.elapsed = str(int(minutes_elapsed)) + "m " + str(total_time % 60) + "s"
				if minutes_elapsed > 60:
					hours_elapsed = minutes_elapsed / 60
					self.elapsed = str(int(hours_elapsed)) + "h " + str(int(minutes_elapsed % 60)) + "m " + str(int(total_time % 60)) + "s"

	def display(self):
		self._progress()
		sys.stdout.write("\r" + self.bar + " " + str(int(self.p)) + "% [ETA: " + self.eta + " | Elapsed: " + self.elapsed + "]     ")
		if self.progress == self.job-1:
			sys.stdout.write("\n")
		sys.stdout.flush()
		self.progress += 1
