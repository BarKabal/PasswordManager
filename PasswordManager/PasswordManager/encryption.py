import passlib.hash
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from hashlib import md5

def AES_encrypt(data, key):
    key_transformed = md5(key.encode('utf8')).digest()
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key_transformed, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
# nwaCTHxIKkclq1cy

def AES_decrypt(data, key):
    key_transformed = md5(key.encode('utf8')).digest()
    cipher = AES.new(key_transformed, AES.MODE_CBC, data[:AES.block_size])
    return unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size).decode("utf8")

def gen_master():
    characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%*()"
    password = ''
    for i in range(16):
        password += random.choice(characters)
    return password

def check_master(master_pass, login, encrypted_login):
    login_decrypted = AES_decrypt(encrypted_login, master_pass)
    return login == login_decrypted