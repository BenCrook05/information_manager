# used when the application is first opened
from datetime import datetime, timedelta, date
from cryptography.fernet import Fernet
import uuid
from backEnd.dbrequests import PyAnyWhereRequests as pr
from backEnd.hasher import Hash
import re
import sqlite3
import base64
from backEnd.encryption import Generate
import socket
import traceback

class Application:     
    @staticmethod
    def __get_server_key():
        server_public_key = pr.get_server_key()
        map(int, server_public_key)
        print(server_public_key)
        return server_public_key
    
    @staticmethod
    def attempt_get_saved_data():
        try:
            db=sqlite3.connect(rf"assets\assetdata.db")
            curs = db.cursor()
            curs.execute("SELECT * FROM CurrentUser")  #will fail if no current user or if table doesn't exist
            data = curs.fetchone()
            curs.close()
            db.close()
            if data is not None:
                print("attempting auto login")
                fernet_key = Generate().generate_fernet()
                encrypted_email = base64.b64decode(data[0].encode("utf-8"))
                encrypted_password = base64.b64decode(data[1].encode("utf-8"))
                email = fernet_key.decrypt(encrypted_email).decode("utf-8")
                password = fernet_key.decrypt(encrypted_password).decode("utf-8")
                data_time_last_login = datetime.strptime(data[2], '%Y-%m-%d %H:%M:%S')
                print(f"email: {email}, password: {password}, date: {data_time_last_login}")
                if data_time_last_login > datetime.now() - timedelta(days=14):    
                    return email, password
            raise ValueError("No saved data")
        except Exception as e:
            return False

    
    @staticmethod
    def save_login_data(email,password):
        db = sqlite3.connect(rf"assets\assetdata.db")
        curs = db.cursor()
        fernet_key = Generate().generate_fernet()
        encrypted_email = fernet_key.encrypt(email.encode("utf-8"))
        encrypted_email_str = base64.b64encode(encrypted_email).decode('utf-8')
        encrypted_password = fernet_key.encrypt(password.encode("utf-8"))
        encrypted_password_str = base64.b64encode(encrypted_password).decode('utf-8')
        curs.execute("CREATE TABLE IF NOT EXISTS CurrentUser(Email VARCHAR(128) primary key, Password VARCHAR(128), Date VARCHAR(128))")
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        curs.execute(f"INSERT INTO CurrentUser VALUES('{encrypted_email_str}','{encrypted_password_str}','{current_time}')")
        curs.close()
        db.commit()
        db.close()

    @staticmethod
    def delete_saved_login_data():
        db = sqlite3.connect(rf"assets\assetdata.db")
        curs = db.cursor()
        curs.execute("DELETE FROM CurrentUser")
        curs.close()
        db.commit()
        db.close()
        
    @staticmethod
    def login(email,password,datadic):
        server_public_key = Application.__get_server_key()
        datadic.add_data("server_public_key",server_public_key)
        mac_address_hash = Hash.create_hash(str(uuid.getnode()).encode("utf-8"), "default")
        stored_password_hash = Hash.create_hash(password.encode('utf-8'), salt_type=email)
        print(f"Stored password hash: {stored_password_hash}")
        comparitive_password_hash = Hash.create_hash(stored_password_hash.encode('utf-8'))
        print(f"Comparitive password hash: {comparitive_password_hash}")
        data = pr.authenticate_password(server_public_key,email,mac_address_hash,comparitive_password_hash)
        print(data)
        return data
    
    @staticmethod
    def login_new_device_request(email,password,datadic):
        server_public_key = Application.__get_server_key()
        datadic.add_data("server_public_key",server_public_key)
        mac_address_hash = Hash.create_hash(str(uuid.getnode()).encode("utf-8"), "default")
        stored_password_hash = Hash.create_hash(password.encode('utf-8'), salt_type=email)
        comparitive_password_hash = Hash.create_hash(stored_password_hash.encode('utf-8'))
        print("application attempting to login new device")
        data = pr.add_new_device_request(server_public_key,email,mac_address_hash,comparitive_password_hash)
        return data
       
    @staticmethod 
    def login_new_device_confirm(email,code, datadic):
        server_public_key = datadic.get_data("server_public_key")
        mac_address_hash = Hash.create_hash(str(uuid.getnode()).encode("utf-8"), "default")
        data = pr.confirm_device_code(server_public_key,email,mac_address_hash,code)
        return data
    
    @staticmethod
    def create_new_account(forename,names,email,password,date_of_birth,phone_number,country,datadic):
        valid_email = re.search(r'\A[\d|a-z]\w*@[\d|a-z]\w*(.[a-z]{2,3}){1,2}\Z',email.lower())
        if valid_email:
            mac_address_hash = Hash.create_hash(str(uuid.getnode()).encode("utf-8"), "default")
            stored_password_hash = Hash.create_hash(password.encode('utf-8'), salt_type=email)
            permanent_public_key = "abc"
            server_public_key = Application.__get_server_key()
            datadic.add_data("server_public_key",server_public_key)
            data = pr.add_new_user(server_public_key,forename,names,email,stored_password_hash,date_of_birth,phone_number,country,permanent_public_key,mac_address_hash)
            
            return data
        else:
            return "INVALID EMAIL"
    
    @staticmethod
    def validate_new_account(email,code,datadic):
        mac_address_hash = Hash.create_hash(str(uuid.getnode()).encode("utf-8"), "default")
        server_public_key = datadic.get_data("server_public_key")
        data = pr.confirm_new_user(server_public_key,email,mac_address_hash,code)
        return data
        
        
    
    
    
    
