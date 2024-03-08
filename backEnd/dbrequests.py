# Description: contains all the requests to the database
import requests
import json
import traceback
from backEnd.encryption import Encrypt, Decrypt, Generate
from datetime import datetime



class PyAnyWhereRequests:
    
    @staticmethod
    def get_server_key():
        data_to_return = PyAnyWhereRequests.send_request("get_server_key")
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            print(traceback.format_exc())
            return PyAnyWhereRequests.get_server_key()
        
    @staticmethod
    def add_new_user(server_public_key, forename, names, client_email, password_hash, date_of_birth, phone_number, country, permanent_public_key, mac_address_hash):
        #generate keys used for encrypting data
        
        #format arguments into dictionary to convert to json
        data = {
            "forename": forename,
            "names": names,
            "client_email": client_email,
            "password_hash": password_hash,
            "date_of_birth": date_of_birth,
            "phone_number": phone_number,
            "country": country,
            "permanent_public_key": permanent_public_key,
            "mac_address_hash": mac_address_hash,
        }
         #encrypts data using symmetric key
        data_to_return = PyAnyWhereRequests.send_request("add_new_user", data) #includes client public key so server can encrypt data using client public key
        try:
            #error will be raised with encryption error so will-rerequest until successful.
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.add_new_user(server_public_key, forename, names, client_email, password_hash, date_of_birth, phone_number, country, permanent_public_key, mac_address_hash)
            
    @staticmethod
    def confirm_new_user(server_public_key, client_email, mac_address_hash, code):
        
        data = {
            "client_email": client_email,
            "mac_address_hash": mac_address_hash,
            "code": code,
        }
        
        data_to_return = PyAnyWhereRequests.send_request("confirm_new_user", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.confirm_new_user(server_public_key, client_email, mac_address_hash, code)
             
    @staticmethod
    def add_new_device_request(server_public_key, client_email, new_mac_address, password):
        
        data = {
            "client_email": client_email,
            "mac_address_hash": new_mac_address,
            "password": password,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("add_new_device", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.add_new_device_request(server_public_key, client_email, new_mac_address, password)
            
    @staticmethod
    def confirm_device_code(server_public_key, client_email, mac_address_hash, code):
        
        data = {
            "client_email": client_email,
            "mac_address_hash": mac_address_hash,
            "code": code,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("confirm_device_code", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.confirm_device_code(server_public_key, client_email, mac_address_hash, code)
               
    @staticmethod
    def authenticate_password(server_public_key, client_email, mac_address_hash, password):
        
        data = {
            "client_email": client_email,
            "mac_address_hash": mac_address_hash,
            "password": password,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("authenticate_password", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.authenticate_password(server_public_key, client_email, mac_address_hash, password)    
            
    @staticmethod
    def reset_client_password(server_public_key, session_key, client_email, new_password_hash, raw_password, new_password_keys):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            "new_password_hash": new_password_hash,
            "raw_password": raw_password,
            "new_password_keys": new_password_keys,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("reset_client_password", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.reset_client_password(server_public_key, session_key, client_email, new_password_hash, raw_password, new_password_keys)
            
            
    @staticmethod
    def get_password_overview(server_public_key, session_key, client_email, include_details):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            "include_details": include_details, #if true, returns all password data, if false, returns only basic information
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("get_password_overview", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.get_password_overview(server_public_key, session_key, client_email, include_details)
            
    @staticmethod
    def get_username(server_public_key, session_key, client_email, passID):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            "passID": passID,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("get_username", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.get_username(server_public_key, session_key, client_email, passID)
            
    @staticmethod
    def get_password(server_public_key, session_key, client_email, passID):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            "passID": passID,
            
        }       
        
        data_to_return = PyAnyWhereRequests.send_request("get_password", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.get_password(server_public_key, session_key, client_email, passID)
            
    @staticmethod
    def get_all_passwords(server_public_key, session_key, client_email):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("get_all_passwords", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.get_all_passwords(server_public_key, session_key, client_email)
            
    @staticmethod
    def set_to_lockdown(server_public_key, session_key, client_email, passID):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            "passID": passID,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("set_to_lockdown", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.set_to_lockdown(server_public_key, session_key, client_email, passID)
            
    @staticmethod
    def remove_lockdown(server_public_key, session_key, client_email, passID):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            "passID": passID,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("remove_lockdown", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.remove_lockdown(server_public_key, session_key, client_email, passID)
            
    @staticmethod
    def add_new_password(server_public_key, session_key, client_email, password, title, url, username, additional_info, password_key):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            "password": password,
            "title": title,
            "url": url,
            "username": username,
            "additional_info": additional_info,
            "password_key": password_key,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("add_new_password", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.add_new_password(server_public_key, session_key, client_email, password, title, url, username, additional_info, password_key)
            
    @staticmethod
    def delete_password(server_public_key, session_key, client_email, passID):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            "passID": passID,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("delete_password", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.delete_password(server_public_key, session_key, client_email, passID)
            
    @staticmethod
    def add_manager(server_public_key, session_key, client_email, new_manager_email, passID):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            "new_manager_email": new_manager_email,
            "passID": passID,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("add_manager", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.add_manager(server_public_key, session_key, client_email, new_manager_email, passID)
            
    @staticmethod
    def get_password_users(server_public_key, session_key, client_email, passID, manager_only=False):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            "passID": passID,
            "manager_only": manager_only,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("get_password_users", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.get_password_users(server_public_key, session_key, client_email, passID, manager_only)
            
    @staticmethod
    def delete_password_instance(server_public_key, session_key, client_email, passID, new_manager_email):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            "passID": passID,
            "new_manager_email": new_manager_email,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("delete_password_instance", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            print(traceback.format_exc())
            return PyAnyWhereRequests.delete_password_instance(server_public_key, session_key, client_email, passID, new_manager_email)
           
    @staticmethod
    def remove_password_user(server_public_key, session_key, client_email, passID, user_email):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            "passID": passID,
            "user_email": user_email,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("remove_password_user", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.remove_password_user(server_public_key, session_key, client_email, passID, user_email)
                
            
    @staticmethod
    def update_password(server_public_key, session_key, client_email, passID, new_info,type):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            "passID": passID,
            "new_info": new_info,
            "type": type,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("update_password", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.update_password(server_public_key, session_key, client_email, passID, new_info,type)    
        
    @staticmethod
    def get_pending_passwordkeys(server_public_key, session_key, client_email):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("get_pending_passwordkeys", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.get_pending_passwordkeys(server_public_key, session_key, client_email)
            
    @staticmethod
    def get_emails_sharing(server_public_key, session_key, requested_email):
        
        data = {
            "session_key": session_key,
            "email": requested_email,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("get_emails_sharing", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.get_emails_sharing(server_public_key, session_key, requested_email)
            
    @staticmethod
    def share_password(server_public_key, session_key, client_email, passID, password_key, recipient_UserID, manager, encrypted_sharing_symmetric_key):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            "passID": passID,
            "password_key": password_key,
            "recipient_UserID": recipient_UserID,
            "manager": manager,
            "encrypted_sharing_symmetric_key": encrypted_sharing_symmetric_key,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("share_password", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.share_password(server_public_key, session_key, client_email, passID, password_key, recipient_UserID, manager, encrypted_sharing_symmetric_key)
            
    @staticmethod
    def insert_pending_keys(server_public_key, session_key, client_email, passID, password_key, accept):
        
        data = {
            "session_key": session_key,
            "client_email": client_email,
            "passID": passID,
            "password_key": password_key,
            "accept": accept,   
        }
        data_to_return = PyAnyWhereRequests.send_request("insert_pending_keys", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.insert_pending_keys(server_public_key, session_key, client_email, passID, password_key, accept)
            
    @staticmethod
    def get_public_key(server_public_key, session_key, recipient_UserID):
        
        data = {
            "session_key": session_key,
            "recipient_UserID": recipient_UserID,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("get_public_key", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.get_public_key(server_public_key, session_key, recipient_UserID)
            
    @staticmethod
    def reset_client_sharing_keys(server_public_key, session_key, new_key, client_email):
        
        data = {
            "session_key": session_key,
            "new_public_key": new_key,
            "client_email": client_email,
            
        }
        
        data_to_return = PyAnyWhereRequests.send_request("update_public_keys", data)
        try:
            formated_data = PyAnyWhereRequests.format_data(data_to_return)
            return formated_data
        except Exception as e:
            return PyAnyWhereRequests.reset_client_sharing_keys(server_public_key, session_key, new_key, client_email)
        
  
    
    @staticmethod
    def format_data(returned_data):
        try:
            if returned_data[0]=="FAILED":
                return "FAILED"
        except:
            pass
        print(f"Returned data: {returned_data}")
        data_to_return = returned_data["data"]["data"]
        return data_to_return
    
        
        
    @staticmethod
    def send_request(request_header, data={}):
        url = "https://BenCrook.eu.pythonanywhere.com/post_endpoint"
        dic_to_send = {
            "request_header": request_header,
            "request_data": data,
        }
        print("Sending request: ", dic_to_send)
        try:
            start_time = datetime.now()
            #all requests use post then handled by server
            response = requests.post(url,json=dic_to_send) 
            #checks request was good before trying to return data
            if response.status_code == 200:
                print(f"\nSuccessful request: {request_header}, Duration: {datetime.now()-start_time}")
                response_data = response.json()  
                return response_data

            print(f"Unsuccessful request, status code: {response.status_code}, request: {request_header}")
        
        except Exception as e:
            return traceback.format_exc() + str(response.status_code)
    
