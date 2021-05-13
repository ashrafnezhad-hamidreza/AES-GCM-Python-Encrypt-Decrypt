from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import binascii



def encrypt_AES_GCM(msg, password, aad):
    salt = get_random_bytes(16)
    secretKey = PBKDF2(password, salt, 32, count=1000000)
    print('AES encryption key:', binascii.hexlify(secretKey))

    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    aesCipher.update(aad)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (aad, salt, ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(encryptedMsg, password):
    (aad, salt, ciphertext, nonce, authTag) = encryptedMsg
    secretKey = PBKDF2(password, salt, 32, count=1000000)
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    aesCipher.update(aad)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext, aad

msg = b'Hamid reza Ashrafnezhad'
password = b'522'
aad = input("Enter your aad: ")


encryptedMsg = encrypt_AES_GCM(msg, password, aad.encode("utf8"))

print("encryptedMsg", {
    'aad' : binascii.hexlify(encryptedMsg[0]),
    'aad': encryptedMsg[1],
    'salt': binascii.hexlify(encryptedMsg[1]),
    'ciphertext': binascii.hexlify(encryptedMsg[2]),
    'aesIV': binascii.hexlify(encryptedMsg[3]),
    'authTag': binascii.hexlify(encryptedMsg[4])
})

print(encryptedMsg)
decryptedMsg, aad_recived = decrypt_AES_GCM(encryptedMsg, password)
aad_recived
print("DecryptedMsg: ", decryptedMsg)
print("AAD recived: ", aad_recived)




