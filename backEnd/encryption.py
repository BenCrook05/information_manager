
import base64
from cryptography.fernet import Fernet
import hashlib
import uuid
import binascii
import backEnd.AsymmetricEncryption.endToEnd_encryption as rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import random
import time
from datetime import datetime
import re
from dotenv import load_dotenv
import os
load_dotenv('/assets/.env')

def encryptdecrypt_directory(data, symmetric_key, encryptor, count=0):
    count += 1
    if isinstance(data, dict):
        for key, value in data.items():
            data[key] = encryptdecrypt_directory(value, symmetric_key, encryptor) #has to treat dic differently as can't iterate through
        return data
    
    elif isinstance(data, (list, tuple, set)):
        encrypted_data = [encryptdecrypt_directory(element, symmetric_key, encryptor) for element in data] 
        #iterates through list and executes encryptdecrpt_directory on each element
        return type(data)(encrypted_data)
    
    elif isinstance(data, str):
        return encryptdecrypt(data, str(symmetric_key), encryptor)
    else:
        return data #doesn't encrypt if not a string (as can't encrypt int and boolean function etc)
    
def encryptdecrypt(data: str, key: str, encrypt: bool):
    
    ADDED_STRING = os.getenv("ADDED_STRING") #stored as environment variable
    ADDED_STRING += key
    ADDED_STRING = ADDED_STRING[-50:]  
    combined_string = ADDED_STRING.encode()
    hashed_key = hashlib.sha256(combined_string).digest()
    fernet_key_base64 = base64.urlsafe_b64encode(hashed_key)
    cipher_suite = Fernet(fernet_key_base64)
    
    if encrypt:
        return cipher_suite.encrypt(data.encode('utf-8')).decode('utf-8')
    else:
        return cipher_suite.decrypt(data.encode('utf-8')).decode('utf-8')

class Encrypt:
    @staticmethod
    def encrypt_key_to_server(data, public_key):
        e, n = public_key
        encrypted_key = rsa.AsyncRSA.encrypt_symmetric_key(data, e, n)
        print(f"encrypted_key: {encrypted_key}")
        return encrypted_key
    
    @staticmethod
    def encrypt_data_to_server(data, key):
        encrypted_data = encryptdecrypt_directory(data, key, True)
        return encrypted_data

    @staticmethod
    def encrypt_password_key_to_share(password_key, symmetric_key):
        #uses Fernet to prevent error (related to special characters) caused by using XOR 
        salt = b'constantSalt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(symmetric_key.encode('utf-8')))
        f = Fernet(key)
        encrypted_password_key = f.encrypt(password_key.encode('utf-8')).decode('utf-8')
        return encrypted_password_key

    @staticmethod
    def encrypt_symmetric_key_sharing(symmetric_key: int, e: int, n: int) -> int:
        encrypted_key = rsa.AsyncRSA.encrypt_symmetric_key(symmetric_key, e, n, increments=3)
        return encrypted_key

    @staticmethod
    def encrypt_password_key(password_key: str,client_permanent_key: bytes) -> str:
        f = Fernet(client_permanent_key)
        encrypted_password_key = f.encrypt(password_key.encode('utf-8'))
        return encrypted_password_key.decode('utf-8') 
    
    @staticmethod
    def encrypt_password(password: str, password_key: str) -> str:
        password_key = password_key.encode('utf-8')
        f = Fernet(password_key)
        encrypted_password = f.encrypt(password.encode('utf-8'))
        return encrypted_password.decode('utf-8') 
    
    
class Decrypt:
    @staticmethod
    def decrypt_key_from_server(data, private_key):
        d, n = private_key
        decrypted_key = rsa.AsyncRSA.decrypt_symmetric_key(data, d, n)
        return decrypted_key
    
    @staticmethod
    def decrypt_data_from_server(data, key):
        decrypted_data = encryptdecrypt_directory(data, key, False)
        return decrypted_data

    @staticmethod
    def decrypt_password_key_to_share(password_key, symmetric_key):
        salt = b'constantSalt'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(symmetric_key.encode('utf-8')))
        f = Fernet(key)
        decrypted_password_key = f.decrypt(password_key.encode('utf-8')).decode('utf-8')
        return decrypted_password_key

    @staticmethod
    def decrypt_symmetric_key_sharing(symmetric_key: int, d: int, n: int) -> int:
        decrypted_key = rsa.AsyncRSA.decrypt_symmetric_key(symmetric_key, d, n, increments=3)
        return decrypted_key

    @staticmethod #symmetric decryption
    def decrypt_password_key(password_key: str,client_permanent_key: bytes) -> str:
        f = Fernet(client_permanent_key)
        decrypted_password_key = f.decrypt(password_key.encode('utf-8'))
        return decrypted_password_key.decode('utf-8')
    
    @staticmethod
    def decrypt_password(password: str, password_key: str) -> str: 
        password = password.encode('utf-8')
        password_key = password_key.encode('utf-8')
        key = Fernet(password_key)
        decrypted_password = key.decrypt(password).decode('utf-8')
        return decrypted_password 

    
class Generate:
    @staticmethod
    def generate_asymmetric_keys():
        e, d, n = rsa.AsyncRSA.generate_keys()
        e = int(e)
        n = int(n)
        d = int(d)
        public_key = [e, n]
        private_key = [d, n]
        return public_key, private_key


    @staticmethod
    def generate_password_key() -> str:
        key = Fernet.generate_key()
        return key.decode('utf-8') 
    
    @staticmethod
    def generate_symmetric_key(length=24):
        key = ""
        for i in range(length):
            random_char = chr(random.randint(0, 9) + ord('0'))
            key += random_char
        return key
    
    @staticmethod
    def generate_client_permanent_key(client_permanent_key: bytes):
        #derives from password and month/year
        client_permanent_key = str(client_permanent_key)
        current_date = str(datetime.now().strftime("/%m/%Y"))
        permanent_key_integer_list = list(map(ord,(client_permanent_key)))
        permanent_key_string_list = list(map(str, permanent_key_integer_list))
        permanent_key_string = ''.join(permanent_key_string_list)
        permanent_key_integer = int(permanent_key_string)
        date_no_characters = re.sub(r'\D', '', current_date)
        date_integer = int(date_no_characters)
        data_string = str(permanent_key_integer % date_integer)
        data_integer_list = list(map(ord, data_string))
        data_integer_string = ''.join(list(map(str, data_integer_list)))
        e, d, n = rsa.AsyncRSA.generate_keys(random=False, seed=data_integer_string)
        return (e,d,n)
    
    @staticmethod
    def generate_fernet(extra=""):
        #TODO
        ADDED_STRING = os.getenv("ADDED_STRING") #stored as environment variable
        ADDED_STRING += extra
        #only 50 characters required for corrent Fernet encryption
        ADDED_STRING = ADDED_STRING[-50:]  #gets last 50 characters
        combined_string = (str(uuid.getnode())+ ADDED_STRING).encode()
        hashed_key = hashlib.sha256(combined_string).digest()
        fernet_key_base64 = base64.urlsafe_b64encode(hashed_key)
        fernet_key = Fernet(fernet_key_base64)
        return fernet_key
    
    @staticmethod
    def validate_symmetric_key(encrypted_symmetric_key, max_length=600000):
        keys = encrypted_symmetric_key.split("-")
        keys.remove("")
        keys = list(map(int, keys))
        for key in keys:
            if key >= max_length:
                time.sleep(0.00001)  #gives opportunity to reset random time seed
                return False
        return True
    
    @staticmethod
    def create_error_check(length=16):
        modulus = random.randint(100,999)
        divisor = random.randint(10**(length-3), 10**(length-2)-1)
        integer_div = divisor // modulus
        real_divisor = integer_div * modulus
        return str(modulus)+str(real_divisor)
    
    @staticmethod
    def validate_error_check(data):
        modulus = int(data[:3])
        real_divisor = int(data[3:])
        if real_divisor % modulus == 0:
            return True
        else:
            return False
        
