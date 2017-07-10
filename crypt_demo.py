import os
import crypt

data = "This is my secret message."
print("\n<<<<<< Plain data >>>>>>")
Encrypted = crypt.ShuffleXOR(data, "secretkey123", UI=True).encrypt()
Decrypted = crypt.ShuffleXOR(Encrypted, "secretkey123", UI=True).decrypt()

print("Original data: " + data)
print("Encrypted data: " + Encrypted)
print("Decrypted data: " + Decrypted)

print("\n<<<<<< File >>>>>>")
crypt.XORFile("test.png", "secretkey123").encrypt("test.png.enc")
crypt.XORFile("test.png.enc", "secretkey123").decrypt("test.png.enc.dec")

print("Original file size: " + str(os.path.getsize("test.png")))
print("Encrypted file size: " + str(os.path.getsize("test.png.enc")))
print("Decrypted file size: " + str(os.path.getsize("test.png.enc.dec")))
