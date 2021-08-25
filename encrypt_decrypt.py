from Crypto.Cipher import AES
import scrypt, os, binascii
import secrets
def encrypt_AES_GCM(msg, password):
    kdfSalt = secrets.token_bytes(1024*1024)
    print(kdfSalt)
    with open('kdf_salt.secret','wb') as _f1:
        _f1.write(kdfSalt)
        
    secretKey = scrypt.hash(password, kdfSalt, N=16384, r=8, p=1, buflen=32)
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (kdfSalt, ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(encryptedMsg, password):
    (kdfSalt, ciphertext, nonce, authTag) = encryptedMsg
    secretKey = scrypt.hash(password, kdfSalt, N=16384, r=8, p=1, buflen=32)
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

msg = b'Message for AES-256-GCM + Scrypt encryption'
password = b's3kr3tp4ssw0rd'
encryptedMsg = encrypt_AES_GCM(msg, password)
print("encryptedMsg", {
    'kdfSalt': binascii.hexlify(encryptedMsg[0]),
    'ciphertext': binascii.hexlify(encryptedMsg[1]),
    'aesIV': binascii.hexlify(encryptedMsg[2]),
    'authTag': binascii.hexlify(encryptedMsg[3])
})

decryptedMsg = decrypt_AES_GCM(encryptedMsg, password)
print("decryptedMsg", decryptedMsg)