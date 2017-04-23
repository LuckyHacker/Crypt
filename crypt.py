from hashlib import sha256
import time, sys, random, math, os, re, shutil
#import chardet # detect data encoding

'''
Simple XOR operation encrypting
'''
class XOR:

	def __init__(self, key, *job):
		self.key = key
		if job:
			self.pb = ProgressBar(job[0])

	def InsertData(self, data):
		self.data = data
		self.KeyMultiplier = int(len(self.data) / len(self.key))
		if self.KeyMultiplier < 1:
			self.KeyMultiplier = 1
		self.key = self.key * self.KeyMultiplier
		while len(self.key) < len(self.data):
			self.key += self.key
		return self._Encrypt()

	def _Encrypt(self):
		'''
		Encrypt function can do the encrypting and decrypting
		with XOR operation.
		'''
		try:
			self.pb.Display()
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
		self.Blocks = []
		self.Keylist = [] # Key chars as decimals
		self.Keyvalues = [] # Values that will used to shuffle blocks
		self.key = key
		self.data = data

	def Encrypt(self):
		if self.UI == True:
			print("Encrypting")

		self._GenSalt()
		self._GetKeyHash(self.salt)
		self._GetBlocks(self.data)
		self._GetKeyValues()

		'''
		XOR whole data with original key and keyhash to ensure that no valid
		password is shown in encrypted file. Also XOR certain blocks with
		salt to strengthen security.
		(Looking for more efficient solution)
		'''

		if self.UI == True:
			StepOneEncrypt = XOR(self.key, len(self.Blocks)*2)
			StepTwoEncrypt = XOR(self.KeyHash)
			StepTwoEncrypt.pb = StepOneEncrypt.pb
		else:
			StepOneEncrypt = XOR(self.key)
			StepTwoEncrypt = XOR(self.KeyHash)

		self.Blocks = list(map(StepOneEncrypt.InsertData, self.Blocks))
		self._PartialEncrypt()
		return self.salt + "".join(list(map(StepTwoEncrypt.InsertData, self.Blocks)))

	def Decrypt(self):
		if self.UI == True:
			print("Decrypting")

		self._GetSalt()
		self._GetKeyHash(self.salt)
		self._GetBlocks(self.data)
		self._GetKeyValues()

		if self.UI == True:
			StepOneDecrypt = XOR(self.key, len(self.Blocks)*2)
			StepTwoDecrypt = XOR(self.KeyHash)
			StepTwoDecrypt.pb = StepOneDecrypt.pb
		else:
			StepOneDecrypt = XOR(self.key)
			StepTwoDecrypt = XOR(self.KeyHash)

		self.Blocks = list(map(StepOneDecrypt.InsertData, self.Blocks))
		self._PartialDecrypt()
		return "".join(list(map(StepTwoDecrypt.InsertData, self.Blocks)))

	def _PartialEncrypt(self): # Encrypt certain blocks with salt while shuffling
		PartialEncrypter = XOR(self.SaltKey)
		AmountBlocksToEncrypt = int(math.sqrt(self.BlockAmount))

		for i in range(AmountBlocksToEncrypt):
			EncryptIndex = (len(self.Blocks) % ((i+1) * AmountBlocksToEncrypt)-1)
			self.Blocks[EncryptIndex] = PartialEncrypter.InsertData(self.Blocks[EncryptIndex])
			self._ShuffleBlocks()


	def _PartialDecrypt(self): # Decrypt certain blocks with salt while shuffling
		DecryptIndexes = []
		PartialDecrypter = XOR(self.SaltKey)
		AmountBlocksToDecrypt = int(math.sqrt(self.BlockAmount))
		for i in range(AmountBlocksToDecrypt): # We need to walk all same indexes backwards that are used in partialencrypter
			DecryptIndexes.append((len(self.Blocks) % ((i+1) * AmountBlocksToDecrypt)-1))

		for i in range(AmountBlocksToDecrypt):
			self._SortBlocks()
			self.Blocks[DecryptIndexes[-(i+1)]] = PartialDecrypter.InsertData(self.Blocks[DecryptIndexes[-(i+1)]])

	def _GetKeyHash(self, salt): # Getting KeyHash from key and salt combination
		self.SaltKey = self.key + salt
		self.KeyHash = sha256(self.SaltKey.encode("utf-8")).hexdigest()

	def _GetSalt(self): # Getting salt from data when decrypting
		self.salt = self.data[:16]
		self.data = self.data[16:]

	def _GenSalt(self): # Generating salt when encrypting
		self.salt = "".join(map(lambda x: chr(random.randint(1, 255)), range(16)))

	def _SortBlocks(self): # Sorting blocks back to original order.
		SortedData = [None] * len(self.Keyvalues)
		DestKeyValues = self.Keyvalues[:]
		self.Keyvalues.sort()
		self.Blocks = list(zip(self.Keyvalues, self.Blocks))
		self.Blocks.sort(key=lambda x: DestKeyValues.index(x[0]))
		self.Blocks = list(map(lambda x: x[1],self.Blocks))
		self.Keyvalues = DestKeyValues

	def _ShuffleBlocks(self): # Shuffle blocks based on self.Keyvalues
		for i in range(len(self.Keyvalues)):
			self.Blocks[i] = (self.Keyvalues[i], self.Blocks[i])
		self.Blocks.sort(key=lambda x: x[0])

		for i in range(len(self.Blocks)):
			self.Blocks[i] = self.Blocks[i][1]

	def _GetBlocks(self, data): # Form blocks from data
		self.BlockSize = math.ceil(math.sqrt(len(data)))
		self.BlockAmount = math.ceil(len(data) / self.BlockSize)
		for i in range(int(self.BlockAmount)):
			self.Blocks.append(data[i*int(self.BlockSize):(i+1)*int(self.BlockSize)])
		del self.data

	def _GetKeyValues(self): # Get self.Keyvalues based on amount of blocks
		for i in range(len(self.Blocks)):
			self.Keylist.append(ord(self.KeyHash[(len(self.KeyHash) % (i+1))-1]))

		j = 0
		BaseValue = 1
		while len(self.Keyvalues) < len(self.Blocks):
			if j < len(self.Keylist):
				Value = self.Keylist[j]
			if Value not in self.Keyvalues: # Use different keyvalues!
				self.Keyvalues.append(Value)
			else:
				'''
				Get value from logarithm last decimals
				'''
				BaseValue += 1
				Value += int(str(math.log(BaseValue)).replace(".", "")[-len(str(j)):])
			j += 1

		'''
		This is needed if padding is not used in the end of data!!
		(Last block needs to stay last) Maybe use padding in the future?
		'''
		m = max(self.Keyvalues)
		self.Keyvalues.remove(m)
		self.Keyvalues.append(m)


'''
Used to encrypt and decrypt files. Path to file and password to encrypt with
are required as parameters.
'''
class XORFile:

	def __init__(self, srcfp, key):
		self.MegaByte = 1048576
		self.srcfp = srcfp
		self.key = key
		self.srcf = open(self.srcfp, "rb")
		self._GetEncoding()

	def _GetEncoding(self): # Detect file encoding
		with open(self.srcfp, "rb") as f:
			data = f.read(1024)

		try:
			data = str(data, "utf-8")
			self.Encoding = "utf-8"
		except:
			data = str(data, "Latin-1")
			self.Encoding = "Latin-1"

	def Encrypt(self, dstfp): # Encrypt data using ShuffleXOR
		self.dstf = open(dstfp, "wb")
		while True:
			data = str(self.srcf.read(self.MegaByte), self.Encoding)
			if data == "": break
			self.dstf.write(bytes(ShuffleXOR(data, self.key).Encrypt(), self.Encoding))

	def Decrypt(self, dstfp): # Decrypt data using ShuffleXOR
		self.dstf = open(dstfp, "wb")
		while True:
			data = str(self.srcf.read(self.MegaByte + 16), self.Encoding)
			if data == "": break
			self.dstf.write(bytes(ShuffleXOR(data, self.key).Decrypt(), self.Encoding))


'''
Used to encrypt and decrypt folders. Path to folder, destination path and key are
required as parameters.
'''
class XORFolder:

	def __init__(self, srcfp, key, UI=False):
		self.MegaByte = 1048576
		self.key = key
		self.UI = UI
		# Path variables
		self.RootFolder = ""
		self.srcfp = srcfp
		self.FilePaths = []
		self.FolderPaths = []

		# Metadata related variables
		self.MetaBeginTag = "[METABEGIN]"
		self.MetaEndTag = "[METAEND]"
		self.MetaData = ""

		self.FoldersBeginTag = "[FOLDERSBEGIN]"
		self.FoldersEndTag = "[FOLDERSEND]"
		self.FoldersSepTag = "[FOLDERSSEP]"

		self.FilepathBeginTag = "[FILEPATHBEGIN]"
		self.FilepathEndTag = "[FILEPATHEND]"
		self.FilepathSepTag = "[FILEPATHSEP]"

		self.FileBeginTag = "[FILEBEGIN]"
		self.FileEndTag = "[FILEEND]"

	def Encrypt(self, dstfp):
		self.RootFolder = ".XORFoldertmp" + os.path.sep
		self.dstfp = dstfp
		self._GetPaths()
		self._MakeFolders()
		self._FormMetaData()

		'''
		XOR every file seperately to temp path
		'''
		pb = ProgressBar(len(self.FilePaths))
		for fp in self.FilePaths:
			if self.UI == True:
				pb.Display()
			XORFile(fp, self.key).Encrypt(self.RootFolder + fp)

		self._FilesToFile()
		shutil.rmtree(self.RootFolder, ignore_errors=True)

	def Decrypt(self, dstfp):
		self.RootFolder = ".XORFoldertmp" + os.path.sep
		self._GetMetaData()
		self._MakeFolders()

		self._FileToFiles()

		self.TmpFolder = self.RootFolder
		self.RootFolder = dstfp + os.path.sep
		self._MakeFolders()

		pb = ProgressBar(len(self.FilePaths))
		for fp in self.FilePaths:
			if self.UI == True:
				pb.Display()
			if fp != "":
				XORFile(self.TmpFolder + fp, self.key).Decrypt(dstfp + os.path.sep + fp)

		shutil.rmtree(self.TmpFolder, ignore_errors=True)

	def _FilesToFile(self): # Move files from temp path to one encrypted file
		with open(self.dstfp, "wb+") as tf: # Format destination file
			tf.write(bytes(self.MetaBeginTag + ShuffleXOR(self.MetaData, self.key).Encrypt() + self.MetaEndTag, "Latin-1"))

		with open(self.dstfp, "ab") as f:
			for fp in self.FilePaths:
				with open(self.RootFolder + fp, "rb") as sf:
					data = sf.read()
					f.write(bytes(self.FileBeginTag, "Latin-1") + data + bytes(self.FileEndTag, "Latin-1"))

	def _FileToFiles(self): # Extract files from one encrypted file
		with open(self.srcfp, "rb") as f:
			data = re.findall(r"\[FILEBEGIN\](.*?)\[FILEEND\]", str(f.read(), "Latin-1"), re.DOTALL)
			for i in range(len(self.FilePaths)):
				if self.FilePaths[i] != "":
					with open(self.RootFolder + self.FilePaths[i], "wb+") as df:
						df.write(bytes(data[i], "Latin-1"))

	def _GetPaths(self): # Get path of folders and files (Encrypting)
		for path, dirs, files in os.walk(self.srcfp):
			self.FolderPaths.append(path)
			for f in files:
				self.FilePaths.append(path + os.path.sep + f)

	def _MakeFolders(self): # Make all folders to destination path
		for path in self.FolderPaths:
			try:
				os.makedirs(self.RootFolder + path)
			except FileExistsError:
				pass

	def _FormMetaData(self): # Form meta data for folders and file paths
		self.MetaData += self.FoldersBeginTag
		for folder in self.FolderPaths:
			self.MetaData += folder + self.FoldersSepTag
		self.MetaData += self.FoldersEndTag

		self.MetaData += self.FilepathBeginTag
		for filename in self.FilePaths:
			self.MetaData += filename + self.FilepathSepTag
		self.MetaData += self.FilepathEndTag

	def _GetMetaData(self): # Get metadata from encrypted file (Decrypting)
		with open(self.srcfp, "rb") as f:
			data = str(f.read(self.MegaByte), "Latin-1")
			while self.MetaBeginTag not in data and self.MetaEndTag not in data:
				data += str(f.read(self.MegaByte), "Latin-1")
		self.MetaData = ShuffleXOR(re.findall(r"\[METABEGIN\](.*?)\[METAEND\]", data, re.DOTALL)[0], self.key).Decrypt()
		self.FolderPaths = re.findall(r"\[FOLDERSBEGIN\](.*?)\[FOLDERSEND\]", self.MetaData, re.DOTALL)[0].split("[FOLDERSSEP]")
		self.FilePaths = re.findall(r"\[FILEPATHBEGIN\](.*?)\[FILEPATHEND\]", self.MetaData, re.DOTALL)[0].split("[FILEPATHSEP]")

'''
Trying to create simple and fast hash function
'''
class LHash:

	def Hash(self, data):
		self.HashInt = sum(list(map(lambda x: ord(x), data)))
		while len(str(self.HashInt)) < 64:
			self.HashInt = self.HashInt**2
		return str(self.HashInt)[:64]


class ProgressBar:

	def __init__(self, job):
		self.Progress = 0
		self.Job = job
		self.StartTime = time.time()

	def _progress(self):
		total_time = int(time.time() - self.StartTime)
		self.eta = "0"
		self.elapsed = "0"
		self.p = float(self.Progress) / float(self.Job) * 100
		self.bar = "[" + "="*int((self.p/float(10)*2)) + " "*(20-int((self.p/float(10)*2))) + "]"
		if self.Job == self.Progress+1:
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

	def Display(self):
		self._progress()
		sys.stdout.write("\r" + self.bar + " " + str(int(self.p)) + "% [ETA: " + self.eta + " | Elapsed: " + self.elapsed + "]     ")
		if self.Progress == self.Job-1:
			sys.stdout.write("\n")
		sys.stdout.flush()
		self.Progress += 1
