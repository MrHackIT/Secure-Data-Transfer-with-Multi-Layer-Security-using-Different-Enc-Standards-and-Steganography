import subprocess
#for qr code

import pyqrcode 
import png
from pyqrcode import QRCode

#for hash stego
from typing import Type
import numpy as np
import cv2

from timeit import timeit
import time

#first function to convert data to binary format as string
#
def bin_convert(data):
    if isinstance(data, str):
        return ''.join([format(ord(i), "08b") for i in data])
    elif isinstance(data, bytes):
        return [format(i, "08b") for i in data]
    elif isinstance(data, np.ndarray):
        return [format(i, "08b") for i in data]
    elif isinstance(data, int):
        return format(data, "08b")
    elif isinstance(data, np.uint8):
        return format(data, "08b")
    else:
        raise TypeError("File not supported.")

#second function to encode secret data into the image file.

def encode_data(image_file_name, secret_evidence_data):
    image = cv2.imread(image_file_name)                 #we are reading the image file  
    n_of_bytes = image.shape[0] * image.shape[1]*3//8                 #capacity
    print("[+] Maximum bytes that can be encoded:", n_of_bytes)
    if len(secret_evidence_data) > n_of_bytes:
        raise ValueError("[!] Image Byte stream is too small, need bigger image_file or less secret_evidence_data.")
    else: 
        print("[+] Encoding secret_evidence_data into Image_File...")
    secret_evidence_data += "======="
    initial_data_index = 0
    bin_secret_evidence_data = bin_convert(secret_evidence_data)                 #Converting secret_evidence_data to binary
    secret_evidence_data_len = len(bin_secret_evidence_data)                 #Size of secret_evidence_data to encode
    for row in image:
        for pixel in row:
            red,green,blue = bin_convert(pixel)                 #RGB to binary format

            if initial_data_index < secret_evidence_data_len:
                pixel[0] = int(red[:-1] + bin_secret_evidence_data[initial_data_index], 2)                 #red pixel as least significant bit
                initial_data_index += 1

            if initial_data_index < secret_evidence_data_len:
                pixel[1] = int(green[:-1] + bin_secret_evidence_data[initial_data_index], 2)                 #green pixel as least significant bit
                initial_data_index += 1

            if initial_data_index < secret_evidence_data_len:
                pixel[2] = int(blue[:-1] + bin_secret_evidence_data[initial_data_index], 2)                 #blue pixel as least significant bit
                initial_data_index += 1
            
            if initial_data_index >= secret_evidence_data_len:
                break                 #once data is encoded, break out. 
    
    return image
                
#third function to decode secret data from the image file.


def decode_data(image_file_name):
    print("[+]==================================================================[+]")    
    print("[+] Extracting Secret Data from the image file...")

    image = cv2.imread(image_file_name)                 #we are reading the image file 
    bin_secret_evidence_data = ""

    for row in image:
        for pixel in row:
            red, green, blue = bin_convert(pixel)
            bin_secret_evidence_data += red[-1]
            bin_secret_evidence_data += green[-1]
            bin_secret_evidence_data += blue[-1]

    no_of_bytes = [bin_secret_evidence_data[i: i+8] for i in range(0, len(bin_secret_evidence_data), 8)]                 #we split in 8-bits

    decoded_secret_evidence_data = ""

    for byte in no_of_bytes:
        decoded_secret_evidence_data += chr(int(byte, 2))
        if decoded_secret_evidence_data[-5:] == "=====":
            break

    return decoded_secret_evidence_data[:-5]


#--------------------


def qr_code(secret_text):
    #Generating the QR code 
    code = pyqrcode.create(secret_text)
    #saving the SVG file 
    #code.svg("secret_qr.svg", scale = 8)
    #saving the PNG file. 
    code.png("secret_qr.png", scale = 6)
#--------------------


def hash(secret_evidence_data):
    encode_image_file = encode_data(image_file_name=input_image_file_name, secret_evidence_data=secret_evidence_data)                 #we encode data into the image file.
    cv2.imwrite(output_image_file_name, encode_image_file)                 #saving the output_file_image
                    
#--------------------
def enc_AES():
    subprocess.call("openssl aes-256-cbc -a -pbkdf2 -salt -in encoded_image_file.png -out encoded.enc", shell=True)
    print("[*] Encrypting Image File...\n[+] Encryption Success!\n")
#--------------------
def enc_DES():
    subprocess.call("openssl des-cbc -a -pbkdf2 -in encoded_image_file.png -out encoded.enc",shell=True)
    print("[*] Encrypting Image File...\n[+] Encryption Success!\n")
            
#--------------------
def enc_RC4():
    subprocess.call("openssl rc4 -a -salt -pbkdf2 -in encoded_image_file.png -out encoded.enc", shell=True)
    print("[*] Encrypting Image File...\n[+] Encryption Success!\n")
        
#--------------------
def dec_AES():
    subprocess.call("openssl aes-256-cbc -a -pbkdf2 -salt -d -in encoded.enc -out QR_IMAGE.PNG",shell=True)
    print("[*] Decrypting Image File...\n[+] Decryption Success!")
            
#--------------------
def dec_DES():
    subprocess.call("openssl des-cbc -a -pbkdf2 -d -in encoded.enc -out QR_IMAGE.PNG",shell=True)
    print("[*] Decrypting Image File...\n[+] Decryption Success!")
            
#--------------------
def dec_RC4():
    subprocess.call("openssl rc4 -a -salt -pbkdf2 -d -in encoded.enc -out QR_IMAGE.PNG",shell=True)
    print("[*] Decrypting Image File...\n[+] Decryption Success!")

#--------------------
def steghide():
    subprocess.call("steghide embed -ef encoded.enc -cf Stego2_IMAGE.JPG -sf Final_Stego.JPG", shell=True)

#--------------------
def steghide_decode():
    print("[+]: Enter Key for Steghide decode:")
    subprocess.call("steghide extract -sf Final_Stego.JPG -xf QR_IMAGE.PNG", shell=True)



#---------------------
print("[+]==================================================================[+]")          
print("[+]=======[SECURE DATA TRANSFER USING MULTIPLE LAYER SECURITY]=======[+]")          
print("[+]==================================================================[+]")  
        
response=input("[+] Hello User, to start type Yes...\n")
if response == "Y" or response == "y" or response == "yes" or response == "Yes":
    print("[+]==================================================================[+]")      
    print("[+]: Welcome User!")
    print("[+]==================================================================[+]")  
    enc_dec_input= input("[+]: Are you here to Encrypt or Decrypt:\n")
    print("[+]==================================================================[+]")  
        
    if enc_dec_input == "Encrypt" or enc_dec_input == "encrypt":
        qr_code_input = input("[+]: Do you have QR Code? \n[+]: Yes, if you have the QR Code\n[+]: No, if you haven't generated QR Code\n")
        if qr_code_input == "Yes" or qr_code_input == "YES" or qr_code_input == "yes": 
            qr_code_hash_input = input("[+]: Is your QR code has embedded HASH for integrity check?\n[+]: Yes, if Hash has been embedded\n[+]: No, if has has not been embedded\n")
            if qr_code_hash_input == "Yes" or qr_code_hash_input == "YES" or qr_code_hash_input == "yes":
                
                enc_algo_input = input("[+]: Choose Algorithm for Encryption \n[+]: AES, DES, RC4 \n")
            if qr_code_hash_input == "No" or qr_code_hash_input == "NO" or qr_code_hash_input == "no":
                #hash code comes here. 
                input_image_file_name = "secret_qr.png"

                output_image_file_name = "encoded_image_file.png"

                secret_evidence_data = input("Input the secret text string for generating hash value")

                encode_image_file = encode_data(image_file_name=input_image_file_name, secret_evidence_data=secret_evidence_data)                 #we encode data into the image file.
                cv2.imwrite(output_image_file_name, encode_image_file)                 #saving the output_file_image
                #execution_time = timeit(lambda:secret_evidence_data, number=1)
                print("hash code")
            else:   
                print("Please choose a valid option") 
        if qr_code_input == "No" or qr_code_input == "NO" or qr_code_input == "no":
            #we write the QR CODE here 
            print("[+]==================================================================[+]")  
            print("[+]: GENERATING QR CODE ............")
            #secret text which we are going to imbed in QR code
            secret_text = input("[+]: Enter The Secret Message You Want To Send.\n")
            #secret_text = input("OLD MAN ! FOCUS ON CLASS, Be creative same old trick again ! LOL")
            #qr_code(secret_text=secret_text)
            execution_time_qr_code = timeit(lambda:qr_code(secret_text=secret_text), number=1)
            execution_time_qr_code_str = str(execution_time_qr_code) 
            print("[+] Execution Time for QR CODE: " + execution_time_qr_code_str)
            print("[+]==================================================================[+]")  
        


            qr_code_hash_input = input("[+]: Is your QR code has embedded HASH for integrity check?\n[+]: Yes, if Hash has been embedded\n[+]: No, if has has not been embedded\n")
            if qr_code_hash_input == "Yes" or qr_code_hash_input == "YES" or qr_code_hash_input == "yes":
                print("Choose from the following Menu!")
                enc_algo_input = input("[+]: Choose Algorithm for Encryption \n[+] AES, DES, RC4 \n")
            if qr_code_hash_input == "No" or qr_code_hash_input == "NO" or qr_code_hash_input == "no":
                #hash code comes here. 
                input_image_file_name = "secret_qr.png"

                output_image_file_name = "encoded_image_file.png"
                print("[+]==================================================================[+]")  
                secret_evidence_data = input("[+]: Enter the Hash value. \n[+]: Type Help if you dont have a hash value.\n") 
                if secret_evidence_data == "Help" or secret_evidence_data == "HELP" or secret_evidence_data == "help":
                    print("[+]==================================================================[+]")
                    print("[+]: Use the following command in Kali Terminal to Generate Hash Value.\n[+]: echo -n string_value_here | sha256sum | awk '{print $1}'")
                    print("[+]==================================================================[+]")
                    secret_evidence_data = input("[+]: Enter the Hash value... \n") 
                    #hash(secret_evidence_data)
                    execution_time_hash = timeit(lambda: hash(secret_evidence_data), number=1)
                    execution_time_hash_str = str(execution_time_hash)
                    print("[+] Execution Time for Embedding Hash: " + execution_time_hash_str)
                else:
                    #hash(secret_evidence_data)
                    execution_time_hash = timeit(lambda: hash(secret_evidence_data), number=1)
                    execution_time_hash_str = str(execution_time_hash)
                    print("[+] Execution Time for Embedding Hash: " + execution_time_hash_str)
                print("[+]==================================================================[+]")
                
            else:   
                print("Please choose a valid option")
                print("test_valid")
        enc_algo_input = input("[+]: Choose Algorithm for Encryption \n[+]: AES, DES, RC4 \n")
        if enc_algo_input == "AES" or enc_algo_input == "Aes" or enc_algo_input == "aes":
            print("[+]==================================================================[+]")  
            #print("AES")
            #enc_AES()
            execution_time_AES = timeit(lambda: enc_AES(), number=1)
            execution_time_AES_str = str(execution_time_AES)
            print("[+]==================================================================[+]")  
            print("[+]: Enter Key for Steghide:")
            #steghide()
            execution_time_steghide = timeit(lambda: steghide(), number=1)
            execution_time_steghide_str = str(execution_time_steghide)
            print("[+] Execution Time for Embedding Image: " + execution_time_steghide_str)
            print("[+]==================================================================[+]")  
            print("[+] Execution Time for AES Encryption: " + execution_time_AES_str)
            execution_time_AES_total = execution_time_AES + execution_time_hash + execution_time_steghide
            execution_time_AES_total_str = str(execution_time_AES_total)
            print("[+]==================================================================[+]") 
            print("[+] Total execution time: AES+HASH+STEGO:" + execution_time_AES_total_str)
            print("[+]==================================================================[+]")
            print("[*]")    
            time.sleep(0.4)
            print("[*]")
            time.sleep(0.4)
            print("[*]")
            time.sleep(0.4)
            print("[*]")
            time.sleep(0.4)
            print("[+]=======[THANKYOU FOR USING MULTI LAYER SECURITY SOFTWARE]=========[+]")
            print("[+]==================================================================[+]")

                
        if enc_algo_input == "DES" or enc_algo_input == "Des" or enc_algo_input == "des":
            print("[+]==================================================================[+]")  
            #print("DES")
            #enc_DES()
            execution_time_DES = timeit(lambda: enc_DES(), number=1)
            execution_time_DES_str = str(execution_time_DES)
            print("[+] Execution Time for DES Encryption: " + execution_time_DES_str)
            print("[+]==================================================================[+]")  
            print("[+]: Enter Key for Steghide:")
            #steghide()
            execution_time_steghide = timeit(lambda: steghide(), number=1)
            execution_time_steghide_str = str(execution_time_steghide)
            print("[+] Execution Time for Embedding Hash: " + execution_time_steghide_str)
            print("[+]==================================================================[+]")  
            print("[+] Execution Time for DES Encryption: " + execution_time_DES_str)
            execution_time_DES_total = execution_time_DES + execution_time_hash + execution_time_steghide
            execution_time_DES_total_str = str(execution_time_DES_total)
            print("[+]==================================================================[+]") 
            print("[+] Total execution time: DES+HASH+STEGO:" + execution_time_DES_total_str)
            print("[+]==================================================================[+]")
            print("[*]")    
            time.sleep(0.4)
            print("[*]")
            time.sleep(0.4)
            print("[*]")
            time.sleep(0.4)
            print("[*]")
            time.sleep(0.4)
            print("[+]=======[THANKYOU FOR USING MULTI LAYER SECURITY SOFTWARE]=========[+]")
            print("[+]==================================================================[+]")
            
        if enc_algo_input == "RC4" or enc_algo_input == "Rc4" or enc_algo_input == "rc4":
            print("[+]==================================================================[+]")  
            #print("RC4")
            #enc_RC4()
            execution_time_RC4 = timeit(lambda: enc_RC4(), number=1)
            execution_time_RC4_str = str(execution_time_RC4)
            print("[+] Execution Time for RC4 Encryption: " + execution_time_RC4_str)
            print("[+]==================================================================[+]")  
            print("[+]: Enter Key for Steghide:")
            #steghide()
            execution_time_steghide = timeit(lambda: steghide(), number=1)
            execution_time_steghide_str = str(execution_time_steghide)
            print("[+] Execution Time for Embedding Hash: " + execution_time_steghide_str)
            print("[+]==================================================================[+]")  
            print("[+] Execution Time for RC4 Encryption: " + execution_time_RC4_str)
            execution_time_RC4_total = execution_time_RC4 + execution_time_hash + execution_time_steghide
            execution_time_RC4_total_str = str(execution_time_RC4_total)
            print("[+]==================================================================[+]") 
            print("[+] Total execution time: RC4+HASH+STEGO:" + execution_time_RC4_total_str)
            print("[+]==================================================================[+]")
            print("[*]")    
            time.sleep(0.4)
            print("[*]")
            time.sleep(0.4)
            print("[*]")
            time.sleep(0.4)
            print("[*]")
            time.sleep(0.4)
            print("[+]=======[THANKYOU FOR USING MULTI LAYER SECURITY SOFTWARE]=========[+]")
            print("[+]==================================================================[+]")




        
                
    elif enc_dec_input == "Decrypt" or enc_dec_input == "decrypt":
        #print("[+]: Enter Key for Steghide decode:")
        #subprocess.call("steghide extract -sf Final_Stego.JPG -xf QR_IMAGE.PNG", shell=True)
        #steghide_decode()
        execution_time_steghide_decode = timeit(lambda: steghide_decode(), number=1)
        execution_time_steghide_decode_str = str(execution_time_steghide_decode)
        print("[+]Execution Time for Extracting Image: " + execution_time_steghide_decode_str) 
        print("[+]==================================================================[+]")
        dec_algo_input = input("[+]: Choose Algorithm for Decryption.\n[+]: AES, DES, RC4 \n")
        print("[+]==================================================================[+]")
        if dec_algo_input == "AES" or dec_algo_input == "Aes" or dec_algo_input == "aes":
            #print("AES")
            #dec_AES()
            execution_time_dec_AES = timeit(lambda: dec_AES(), number=1)
            execution_time_dec_AES_str = str(execution_time_dec_AES)
            print("[+] Execution Time for AES Decryption: " + execution_time_dec_AES_str)
            #--------------------------------
            integrity_check = input("[+]: Check integrity of Image file Y/N\n")
            if integrity_check == "Y" or integrity_check == "y":
                hash_with_second_user = input("[+]: Enter the Hash value. \n[+]: Type Help if you dont have a hash value.\n")
                if hash_with_second_user == "Help" or hash_with_second_user == "HELP" or hash_with_second_user =="help":
                    print("[+]==================================================================[+]")   
                    print("Use the following command in Kali Terminal to Generate Hash Value.\n echo -n string_value_here | sha256sum | awk '{print $1}'")
                    
                    user2_hash = input("[+]: Enter the Hash value.\n") 
                    output_image_file_name = "encoded_image_file.png"
                    decoded_secret_evidence_data = decode_data(output_image_file_name)
                    print("[+] Secret Data:", decoded_secret_evidence_data)
                    execution_time_hash_decode = timeit(lambda: decoded_secret_evidence_data, number=1)
                    execution_time_hash_decode_str = str(execution_time_hash_decode)
                    #print("[+] Execution time for extracting Hash: " +execution_time_hash_decode_str)
                    print("[+]==================================================================[+]")  
                    execution_time_dec_AES_total = execution_time_dec_AES + execution_time_hash_decode_str + execution_time_steghide_decode_str
                    execution_time_dec_AES_total_str = str(execution_time_dec_AES_total)
                    print("Total execution time: AES+HASH+STEGO:" + execution_time_dec_AES_total_str)
                    print("[+]==================================================================[+]")
                    if hash_with_second_user == decoded_secret_evidence_data or user2_hash == decoded_secret_evidence_data:
                        print("[+]===============[INTEGRITY CHECK SUCCESSFULL]======================[+]")
                        print("[+]==================================================================[+]")
                    if hash_with_second_user != decoded_secret_evidence_data or user2_hash != decoded_secret_evidence_data:
                        print("[+]===================[INTEGRITY CHECK FAILED]=======================[+]")
                        print("[+]==================================================================[+]")
                    print("[*]")    
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)

                    print("[+]=======[THANKYOU FOR USING MULTI LAYER SECURITY SOFTWARE]=========[+]")
                    print("[+]==================================================================[+]")
                
                
                else:
                    #user2_hash = input("Enter the Hash value... \n") 
                    output_image_file_name = "encoded_image_file.png"
                    decoded_secret_evidence_data = decode_data(output_image_file_name)
                    print("[+] Secret Data:", decoded_secret_evidence_data)
                    execution_time_hash_decode = timeit(lambda: decoded_secret_evidence_data, number=1)
                    execution_time_hash_decode_str = str(execution_time_hash_decode)
                    #print("[+] Execution time for extracting Hash: " +execution_time_hash_decode_str)
                    print("[+]==================================================================[+]")  
                    execution_time_dec_AES_total = execution_time_dec_AES + execution_time_hash_decode + execution_time_steghide_decode
                    execution_time_dec_AES_total_str = str(execution_time_dec_AES_total)
                    print("Total execution time: AES+HASH+STEGO:" + execution_time_dec_AES_total_str)
                    print("[+]==================================================================[+]")
                    if hash_with_second_user == decoded_secret_evidence_data:
                        print("[+]=================[INTEGRITY CHECK SUCCESSFULL]====================[+]")
                        print("[+]==================================================================[+]")
                    if hash_with_second_user != decoded_secret_evidence_data:
                        print("[+]===================[INTEGRITY CHECK FAILED]=======================[+]")
                        print("[+]==================================================================[+]")
                    print("[*]")
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[+]=======[THANKYOU FOR USING MULTI LAYER SECURITY SOFTWARE]=========[+]")
                    print("[+]==================================================================[+]")

            #--------------------------------

        
        if dec_algo_input == "DES" or dec_algo_input == "Des" or dec_algo_input == "des":
            #print("DES")
            #dec_DES()
            execution_time_dec_DES = timeit(lambda: dec_DES(), number=1)
            execution_time_dec_DES_str = str(execution_time_dec_DES)
            print("[+] Execution Time for DES Decryption: " + execution_time_dec_DES_str)
            print("[+]==================================================================[+]")
#-------------------
            integrity_check = input("[+]: Check integrity of Image file Y/N\n")
            if integrity_check == "Y" or integrity_check == "y":
                hash_with_second_user = input("[+]: Enter the Hash value. \n[+]: Type Help if you dont have a hash value.\n")
                if hash_with_second_user == "Help" or hash_with_second_user == "HELP" or hash_with_second_user =="help":
                    print("[+]==================================================================[+]")   
                    print("Use the following command in Kali Terminal to Generate Hash Value.\n echo -n string_value_here | sha256sum | awk '{print $1}'")
                    
                    user2_hash = input("[+]: Enter the Hash value.\n") 
                    output_image_file_name = "encoded_image_file.png"
                    decoded_secret_evidence_data = decode_data(output_image_file_name)
                    print("[+] Secret Data:", decoded_secret_evidence_data)
                    execution_time_hash_decode = timeit(lambda: decoded_secret_evidence_data, number=1)
                    execution_time_hash_decode_str = str(execution_time_hash_decode)
                    #print("[+] Execution time for extracting Hash: " +execution_time_hash_decode_str)
                    print("[+]==================================================================[+]")  
                    execution_time_dec_DES_total = execution_time_dec_DES + execution_time_hash_decode + execution_time_steghide_decode
                    execution_time_dec_DES_total_str = str(execution_time_dec_DES_total)
                    print("[+]==================================================================[+]")
                    if hash_with_second_user == decoded_secret_evidence_data or user2_hash == decoded_secret_evidence_data:
                        print("[+]===============[INTEGRITY CHECK SUCCESSFULL]======================[+]")
                        print("[+]==================================================================[+]")
                    if hash_with_second_user != decoded_secret_evidence_data or user2_hash != decoded_secret_evidence_data:
                        print("[+]===================[INTEGRITY CHECK FAILED]=======================[+]")
                        print("[+]==================================================================[+]")
                    print("Total execution time: DES+HASH+STEGO:" + execution_time_dec_DES_total_str)
                    print("[*]")    
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[+]=======[THANKYOU FOR USING MULTI LAYER SECURITY SOFTWARE]=========[+]")
                    print("[+]==================================================================[+]")
                    
                    #print("[+]==================================================================[+]")
                
                
                else:
                    #user2_hash = input("Enter the Hash value... \n") 
                    output_image_file_name = "encoded_image_file.png"
                    decoded_secret_evidence_data = decode_data(output_image_file_name)
                    print("[+] Secret Data:", decoded_secret_evidence_data)
                    execution_time_hash_decode = timeit(lambda: decoded_secret_evidence_data, number=1)
                    execution_time_hash_decode_str = str(execution_time_hash_decode)
                    #print("[+] Execution time for extracting Hash: " +execution_time_hash_decode_str)
                    print("[+]==================================================================[+]")  
                    execution_time_dec_DES_total = execution_time_dec_DES + execution_time_hash_decode + execution_time_steghide_decode
                    execution_time_dec_DES_total_str = str(execution_time_dec_DES_total)
                    print("Total execution time: DES+HASH+STEGO:" + execution_time_dec_DES_total_str)
                    print("[+]==================================================================[+]")
                    if hash_with_second_user == decoded_secret_evidence_data:
                        print("[+]=================[INTEGRITY CHECK SUCCESSFULL]====================[+]")
                        print("[+]==================================================================[+]")
                    if hash_with_second_user != decoded_secret_evidence_data:
                        print("[+]===================[INTEGRITY CHECK FAILED]=======================[+]")
                        print("[+]==================================================================[+]")
                    print("[*]")
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[+]=======[THANKYOU FOR USING MULTI LAYER SECURITY SOFTWARE]=========[+]")
                    print("[+]==================================================================[+]")

#----------------
            
        if dec_algo_input == "RC4" or dec_algo_input == "Rc4" or dec_algo_input == "rc4":
            #print("RC4")
            #dec_RC4()
            execution_time_dec_RC4 = timeit(lambda: dec_RC4(), number=1)
            execution_time_dec_RC4_str = str(execution_time_dec_RC4)
            print("[+] Execution Time for Embedding Hash: " + execution_time_dec_RC4_str)
            integrity_check = input("[+]: Check integrity of Image file Y/N\n")
            if integrity_check == "Y" or integrity_check == "y":
                hash_with_second_user = input("[+]: Enter the Hash value. \n[+]: Type Help if you dont have a hash value.\n")
                if hash_with_second_user == "Help" or hash_with_second_user == "HELP" or hash_with_second_user =="help":
                    print("[+]==================================================================[+]")   
                    print("Use the following command in Kali Terminal to Generate Hash Value.\n echo -n string_value_here | sha256sum | awk '{print $1}'")
                    
                    user2_hash = input("[+]: Enter the Hash value.\n") 
                    output_image_file_name = "encoded_image_file.png"
                    decoded_secret_evidence_data = decode_data(output_image_file_name)
                    print("[+] Secret Data:", decoded_secret_evidence_data)
                    execution_time_hash_decode = timeit(lambda: decode_data(), number=1)
                    execution_time_hash_decode_str = str(execution_time_hash_decode)
                    #print("[+] Execution time for extracting Hash: " +execution_time_hash_decode_str)
                    print("[+]==================================================================[+]")  
                    execution_time_dec_RC4_total = execution_time_dec_RC4 + execution_time_hash_decode + execution_time_steghide_decode
                    execution_time_dec_RC4_total_str = str(execution_time_dec_RC4_total)
                    print("Total execution time: RC4+HASH+STEGO:" + execution_time_dec_RC4_total_str)
                    print("[+]==================================================================[+]")
                    if hash_with_second_user == decoded_secret_evidence_data or user2_hash == decoded_secret_evidence_data:
                        print("[+]===============[INTEGRITY CHECK SUCCESSFULL]======================[+]")
                        print("[+]==================================================================[+]")
                    if hash_with_second_user != decoded_secret_evidence_data or user2_hash != decoded_secret_evidence_data:
                        print("[+]===================[INTEGRITY CHECK FAILED]=======================[+]")
                        print("[+]==================================================================[+]")
                    print("[*]")    
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[+]=======[THANKYOU FOR USING MULTI LAYER SECURITY SOFTWARE]=========[+]")
                    print("[+]==================================================================[+]")
                
                
                else:
                    #user2_hash = input("Enter the Hash value... \n") 
                    output_image_file_name = "encoded_image_file.png"
                    decoded_secret_evidence_data = decode_data(output_image_file_name)
                    print("[+] Secret Data:", decoded_secret_evidence_data)
                    execution_time_hash_decode = timeit(lambda: decoded_secret_evidence_data, number=1)
                    execution_time_hash_decode_str = str(execution_time_hash_decode)
                    #print("[+] Execution time for extracting Hash: " +execution_time_hash_decode_str)
#---------------------
                    print("[+]==================================================================[+]")  
                    execution_time_dec_RC4_total = execution_time_dec_RC4 + execution_time_hash_decode + execution_time_steghide_decode
                    print("TESTEST")
                    print(execution_time_steghide_decode)
                    execution_time_steghide_decode_float = float(execution_time_steghide_decode)
                    print("STGEHIDE")
                    print(execution_time_steghide_decode_float)
                    print(execution_time_dec_RC4_total)
                    execution_time_dec_RC4_total_str = str(execution_time_dec_RC4_total)
                    print("Total execution time: RC4+HASH+STEGO:" + execution_time_dec_RC4_total_str)
                    print("[+]==================================================================[+]")
                    if hash_with_second_user == decoded_secret_evidence_data:
                        print("[+]=================[INTEGRITY CHECK SUCCESSFULL]====================[+]")
                        print("[+]==================================================================[+]")
                    if hash_with_second_user != decoded_secret_evidence_data:
                        print("[+]===================[INTEGRITY CHECK FAILED]=======================[+]")
                        print("[+]==================================================================[+]")
                    print("[*]")
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[*]")
                    time.sleep(0.4)
                    print("[+]=======[THANKYOU FOR USING MULTI LAYER SECURITY SOFTWARE]=========[+]")
                    print("[+]==================================================================[+]")
                
            
            
                

#ADD SYS INFO COMMANDS 
#add image stego 

        
    
#    else:
 #       print("Please choose a valid option")



#STEGO2 FILE 

#for encoding
#subprocess.call("steghide embed -ef encoded_image_file.PNG -cf Stego2_IMAGE.JPG -sf Final_Stego.JPG -p password", shell=True)



#for decoding
#subprocess.call("steghide extract -sf Final_Stego.JPG -xf QR_IMAGE.PNG", shell=True)


