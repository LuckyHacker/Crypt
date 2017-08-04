# Copyright (C) 2016-2017 luckyhacker.com
from hashlib import sha256
import random
import math
import os
import re
import shutil
import itertools

from progressbar import ProgressBar


'''
Simple XOR operation encrypting
'''


class XOR:

    def __init__(self, key, *job):
        self.key = key
        self.job = job
        if self.job:
            self.pb = ProgressBar(job[0])

    def insert(self, data):
        cycle_key = itertools.cycle(self.key)
        if self.job:
            self.pb.display()

        return "".join(list(map(lambda x, y: chr(ord(x) ^ ord(y)), data, cycle_key)))


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
        self.keylist = []  # Key chars as decimals
        self.keyvalues = []  # Values that will used to shuffle blocks
        self.key = key
        self.data = data

    def encrypt(self):
        if self.UI:
            print("Encrypting")

        self._gen_salt()
        self._get_keyhash()
        self._get_blocks(self.data)
        self._get_keyvalues()

        '''
        XOR whole data with original key and keyhash to ensure that no valid
        password is shown in encrypted file. Also XOR certain blocks with
        salt to strengthen security.
        (Looking for more efficient solution)
        '''
        if self.UI:
            step_one_encrypt = XOR(self.key, len(self.blocks) * 2)
            step_two_encrypt = XOR(self.keyhash)
            step_two_encrypt.pb = step_one_encrypt.pb
        else:
            step_one_encrypt = XOR(self.key)
            step_two_encrypt = XOR(self.keyhash)

        self.blocks = list(map(step_one_encrypt.insert, self.blocks))
        self._partial_encrypt()
        return self.salt + "".join(list(map(step_two_encrypt.insert, self.blocks)))

    def decrypt(self):
        if self.UI:
            print("Decrypting")

        self._get_salt()
        self._get_keyhash()
        self._get_blocks(self.data)
        self._get_keyvalues()

        if self.UI:
            step_one_decrypt = XOR(self.key, len(self.blocks) * 2)
            step_two_decrypt = XOR(self.keyhash)
            step_two_decrypt.pb = step_one_decrypt.pb
        else:
            step_one_decrypt = XOR(self.key)
            step_two_decrypt = XOR(self.keyhash)

        self.blocks = list(map(step_one_decrypt.insert, self.blocks))
        self._partial_decrypt()
        return "".join(list(map(step_two_decrypt.insert, self.blocks)))

    def _partial_encrypt(self):  # Encrypt certain blocks with salt while shuffling
        partial_encrypter = XOR(self.saltkey)
        amount_blocks_to_encrypt = int(math.sqrt(self.block_amount))

        for i in range(amount_blocks_to_encrypt):
            encrypt_index = (len(self.blocks) %
                             ((i + 1) * amount_blocks_to_encrypt) - 1)
            self.blocks[encrypt_index] = partial_encrypter.insert(
                self.blocks[encrypt_index])
            self._shuffle_blocks()

    def _partial_decrypt(self):  # Decrypt certain blocks with salt while shuffling
        partial_decrypter = XOR(self.saltkey)
        amount_blocks_to_decrypt = int(math.sqrt(self.block_amount))
        # We need to walk all same indexes backwards that are used in partialencrypter
        decrypt_indexes = list(map(lambda i: (len(self.blocks) % (
            (i + 1) * amount_blocks_to_decrypt) - 1), range(amount_blocks_to_decrypt)))

        for i in range(amount_blocks_to_decrypt):
            self._sort_blocks()
            self.blocks[decrypt_indexes[-(i + 1)]] = partial_decrypter.insert(
                self.blocks[decrypt_indexes[-(i + 1)]])

    def _get_keyhash(self):  # Getting KeyHash from key and salt combination
        self.saltkey = self.key + self.salt
        self.keyhash = sha256(self.saltkey.encode("utf-8")).hexdigest()

    def _get_salt(self):  # Getting salt from data when decrypting
        self.salt = self.data[:16]
        self.data = self.data[16:]

    def _gen_salt(self):  # Generating salt when encrypting
        self.salt = str(os.urandom(16), "latin-1")

    def _sort_blocks(self):  # Sorting blocks back to original order.
        dest_key_values = self.keyvalues[:]
        self.keyvalues.sort()
        self.blocks = list(zip(self.keyvalues, self.blocks))
        self.blocks.sort(key=lambda x: dest_key_values.index(x[0]))
        self.blocks = list(map(lambda x: x[1], self.blocks))
        self.keyvalues = dest_key_values

    def _shuffle_blocks(self):  # Shuffle blocks based on self.Keyvalues
        self.blocks = list(
            map(lambda x, y: (x, y), self.keyvalues, self.blocks))
        self.blocks.sort(key=lambda x: x[0])
        self.blocks = list(map(lambda x: x[1], self.blocks))

    def _get_blocks(self, data):  # Form blocks from data
        self.block_size = math.ceil(math.sqrt(len(data)))
        self.block_amount = math.ceil(len(data) / self.block_size)
        for i in range(int(self.block_amount)):
            self.blocks.append(
                data[i * int(self.block_size):(i + 1) * int(self.block_size)])
        del self.data

    def _get_keyvalues(self):  # Get self.Keyvalues based on amount of blocks
        for i in range(len(self.blocks)):
            self.keylist.append(
                ord(self.keyhash[(len(self.keyhash) % (i + 1)) - 1]))

        j = 0
        base_value = 1
        while len(self.keyvalues) < len(self.blocks):
            if j < len(self.keylist):
                value = self.keylist[j]
            if value not in self.keyvalues:  # Use different keyvalues!
                self.keyvalues.append(value)
            else:
                '''
                Get value from logarithm last decimals
                '''
                base_value += 1
                value += int(str(math.log(base_value)
                                 ).replace(".", "")[-len(str(j)):])
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
        self.buffer_size = 1048576 * 50  # 50MB
        self.srcfp = srcfp
        self.key = key
        self.srcf = open(self.srcfp, "rb")
        self._get_encoding()

    def _get_encoding(self):  # Detect file encoding
        with open(self.srcfp, "rb") as f:
            data = f.read(1024)

        try:
            data = str(data, "utf-8")
            self.encoding = "utf-8"
        except:
            data = str(data, "latin-1")
            self.encoding = "latin-1"

    def encrypt(self, dstfp):  # Encrypt data using ShuffleXOR
        self.dstf = open(dstfp, "wb")
        import time
        while True:
            data = str(self.srcf.read(self.buffer_size), self.encoding)
            if data == "":
                break
            self.dstf.write(
                bytes(ShuffleXOR(data, self.key).encrypt(), self.encoding))

    def decrypt(self, dstfp):  # Decrypt data using ShuffleXOR
        self.dstf = open(dstfp, "wb")
        while True:
            data = str(self.srcf.read(self.buffer_size + 16), self.encoding)
            if data == "":
                break
            self.dstf.write(
                bytes(ShuffleXOR(data, self.key).decrypt(), self.encoding))


'''
Used to encrypt and decrypt folders. Path to folder, destination path and key are
required as parameters.
'''


class XORFolder:

    def __init__(self, srcfp, key, UI=False):
        self.buffer_size = 1048576 * 50  # 50MB
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
            if self.UI:
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
            if self.UI:
                pb.display()
            if fp != "":
                XORFile(self.tmp_folder + fp,
                        self.key).decrypt(dstfp + os.path.sep + fp)

        shutil.rmtree(self.tmp_folder, ignore_errors=True)

    def _files_to_file(self):  # Move files from temp path to one encrypted file
        with open(self.dstfp, "wb+") as tf:  # Format destination file
            tf.write(bytes(self.meta_begin_tag + ShuffleXOR(self.meta_data,
                                                            self.key).encrypt() + self.meta_end_tag, "latin-1"))

        with open(self.dstfp, "ab") as f:
            for fp in self.file_paths:
                with open(self.root_folder + fp, "rb") as sf:
                    data = sf.read()
                    f.write(bytes(self.file_begin_tag, "latin-1") +
                            data + bytes(self.file_end_tag, "latin-1"))

    def _file_to_files(self):  # Extract files from one encrypted file
        with open(self.srcfp, "rb") as f:
            data = re.findall(r"\[FILEBEGIN\](.*?)\[FILEEND\]",
                              str(f.read(), "latin-1"), re.DOTALL)
            for i in range(len(self.file_paths)):
                if self.file_paths[i] != "":
                    with open(self.root_folder + self.file_paths[i], "wb+") as df:
                        df.write(bytes(data[i], "latin-1"))

    def _get_paths(self):  # Get path of folders and files (Encrypting)
        for path, dirs, files in os.walk(self.srcfp):
            self.folder_paths.append(path)
            for f in files:
                self.file_paths.append(path + os.path.sep + f)

    def _make_folders(self):  # Make all folders to destination path
        for path in self.folder_paths:
            try:
                os.makedirs(self.root_folder + path)
            except FileExistsError:
                pass

    def _form_meta_data(self):  # Form meta data for folders and file paths
        self.meta_data += self.folders_begin_tag
        for folder in self.folder_paths:
            self.meta_data += folder + self.folders_sep_tag
        self.meta_data += self.folders_end_tag

        self.meta_data += self.filepath_begin_tag
        for filename in self.file_paths:
            self.meta_data += filename + self.filepath_sep_tag
        self.meta_data += self.filepath_end_tag

    def _get_meta_data(self):  # Get metadata from encrypted file (Decrypting)
        with open(self.srcfp, "rb") as f:
            data = str(f.read(self.buffer_size), "latin-1")
            while self.meta_begin_tag not in data and self.meta_end_tag not in data:
                data += str(f.read(self.buffer_size), "latin-1")
        self.meta_data = ShuffleXOR(re.findall(
            r"\[METABEGIN\](.*?)\[METAEND\]", data, re.DOTALL)[0], self.key).decrypt()
        self.folder_paths = re.findall(
            r"\[FOLDERSBEGIN\](.*?)\[FOLDERSEND\]", self.meta_data, re.DOTALL)[0].split("[FOLDERSSEP]")
        self.file_paths = re.findall(
            r"\[FILEPATHBEGIN\](.*?)\[FILEPATHEND\]", self.meta_data, re.DOTALL)[0].split("[FILEPATHSEP]")
