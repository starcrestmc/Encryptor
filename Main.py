# Original tool built by StarcrestMC - https://github.com/starcrestmc/Encryptor-v6

from random import randrange as rr
from random import choice as ch
import time as t
import os
try:
    import imghdr
    import secrets
    import json
    import base64
    import string
    from hashlib import sha256
    import getpass
    import pgpy
    import shutil
    import pickle as pk
except:
    reqs = input("Would you like to install the Requirements? [Y]es/[N]o: ")
    if reqs.lower() == "y":
        os.system('cmd /c "color a & echo [Python]: Installing Requirements & @echo off & pip install -r requirements.txt & timeout /t 3 /nobreak"')
    else:
        print("This script wont run without pgpy, hashlib, nltk and cryptography")
        print("Please install manually if you want to use this")
        t.sleep(3)
        exit()

from EXTRAMODULES import PGPmsg
from EXTRAMODULES import pre

import nltk
from nltk.corpus import brown
from nltk import pos_tag
nltk.download('brown')
nltk.download('averaged_perceptron_tagger_eng')

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

switchcase = None # set the case to blank
PGPmsg.POST() # Make sure PGP Keys are Generated (POST = Power On Self Test)


def list_generate(file_name):
    class pt:
        @staticmethod
        def A():
            crs = ['@', '_', '!', '%', '^', '&', '>', '<', '?', '.', '#', '~', '-']
            x = rr(1, 13)
            return crs[x]

    # Word file caches
        def B(): # adverbs
            try:
                with open("av.pkl", "rb") as f:
                    av_ls = pk.load(f)
            except FileNotFoundError:
                av_ls = pre.av()
            av = ch(av_ls)
            return av

        def C(): # verbs
            try:
                with open("v.pkl", "rb") as f:
                    v_ls = pk.load(f)
            except FileNotFoundError:
                v_ls = pre.v()
            v = ch(v_ls)
            return v

        def D(): # middle character
            chs = ['(_)', '[_]', '{_}', '(-)', '[-]', '{-}', '(+)', '[+]', '{+}', '(=)', '[=]', '{=}', '(&)', '[&]', '{&}', '(%)', '[%]', '{%}']
            x = rr(0, 18) # Maximum Security
            return chs[x]

        def E(): #adjective
            try:
                with open("aj.pkl", "rb") as f:
                    aj_ls = pk.load(f)
            except FileNotFoundError:
                aj_ls = pre.aj()
            aj = ch(aj_ls)
            return aj

        def F(): #noun
            try:
                with open("n.pkl", "rb") as f:
                    n_ls = pk.load(f)
            except FileNotFoundError:
                n_ls = pre.n()
            n = ch(n_ls)
            return n

        def G(): # character either side of the end part
            c1 = ['(#', '[#', '{#', '($', '[$', '{$', '(=', '[=', '{='] # Security LV.1 could be index 0-2 and Security LV 2 could be index 3-11
            mpr = {'(#': ')', '[#': ']', '{#': '}', '($': ')', '[$': ']', '{$': '}', '(=': ')', '[=': ']', '{=': '}'}
            a = rr(0, 8) # Maximum Security
            l = c1[a]
            r = mpr[l]
            return l, r

        def H():
            return rr(10000, 99999) #Maximum Security

    def joiner(file):
            done = 0
            print("Verbose: Making Passwords..")
            for i in range(1028): # make 1028 passwords
                    a = pt.A()
                    b = pt.B()
                    c = pt.C()
                    d = pt.D()
                    e = pt.E()
                    f = pt.F()
                    lr = pt.G()
                    gL = lr[0]
                    g = pt.H()
                    gR = lr[1]
                    finished_password = f'{a}{b.title()}{c.title()}{d}{e.title()}{f.title()}{str(gL)}{g}{str(gR)}'
                    done += 1
                    print(f'Made {done} of 1028')
                    data.append(finished_password)
                
            with open(f'Vault/{filename}.json', 'w') as f:
                    #print("\nWriting, Please Wait...")
                    json.dump(data, f, indent=4)
                    print("Data Successfully Written!")
    
    joiner(file_name)
# Key:
# 0000 | u+200b is ZWSP
# 0001 | u+200c is ZWNJ
# 0010 | u+200d is ZWJ
# 0011 | u+2060 is WJ
# 0100 | u+200e is LTRM
# 0101 | u+200f is RTLM
# 0110 | u+2066 is LTRI
# 0111 | u+2067 is RTLI
# 1000 | u+2068 is FSI
# 1001 | u+2069 is PDI
# 1010 | u+180e is Mongolian Vowel Separator
# 1011 | u+180b is Mongolian Free Variation Selector 1
# 1100 | u+180c is Mongolian Free Variation Selector 2
# 1101 | u+180d is Mongolian Free Variation Selector 3
# 1110 | u+206a is Inhibit Symmetric Swapping
# 1111 | u+206b is Active Symmetric Swapping


def hide_text(text):
    key_map = ['\u200b', '\u200c', '\u200d', '\u2060', '\u200e', '\u200f', '\u2066', '\u2067', '\u2068', '\u2069', '\u180e', '\u180b', '\u180c', '\u180d', '\u206a', '\u206b']
    # Key map defined
    binary_data = ''.join(format(ord(c), '08b') for c in text)
    hidden_chars = []
    for i in range(0, len(binary_data), 4):
        four_bit_part = binary_data[i:i+4]  # Break into 4 parts
        index_position = int(four_bit_part, 2) # convert binary to integer
        hidden_chars.append(key_map[index_position])
    return ''.join(hidden_chars)

    # Old method using only 2 chars

    # Convert string to a sequence of 0s and 1s
    #binary_data = ''.join(format(ord(c), '08b') for c in text)
    
    # Map 0 to ZWSP (\u200b) and 1 to ZWJ (\u200d)
    #hidden = binary_data.replace('0', '\u200b').replace('1', '\u200d')



def show_text(text):
    # 1. Use the exact same key_map list
    key_map = ['\u200b', '\u200c', '\u200d', '\u2060', '\u200e', '\u200f', '\u2066', '\u2067', '\u2068', '\u2069', '\u180e', '\u180b', '\u180c', '\u180d', '\u206a', '\u206b']
    binary_chunks = []
    for char in text: # Read the hidden text character by character
        if char in key_map:
            index = key_map.index(char) # Find the index of this char
            four_bit_part = format(index, '04b') # Convert into a 4-bit binary string (padded with 0's)
            binary_chunks.append(four_bit_part)
            
    full_binary = ''.join(binary_chunks) # 3. Combine all 4-bit parts into one massive binary string
    decoded_string = [] # 4. Break the binary string back into 8-bit bytes and convert to actual characters
    for i in range(0, len(full_binary), 8):
        byte_part = full_binary[i:i+8]
        # Convert 8-bit binary string to integer, then integer to character
        decoded_string.append(chr(int(byte_part, 2)))
    return ''.join(decoded_string)

def derive_key_from_password(password, salt=None):
    if salt is None:
        salt = os.urandom(32)  # 256-bit salt for extra entropy
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

def encrypt_files_aes(plaintext, password): # FOR ENCRYPTING FILES ONLY

    # Generate a random salt (32 bytes for extra entropy)
    salt = os.urandom(32)  # 256-bit salt

    # Derive a strong 256-bit key
    key, _ = derive_key_from_password(password, salt)

    # Generate a 12-byte IV (Nonce) as required by AES-GCM
    iv = os.urandom(12)  # 12-byte IV (standard for AES-GCM)

    # Create AES-GCM cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())

    # Generate a random AAD (Associated Data)
    aad = os.urandom(32)  # 32 bytes of random associated data

    # Encrypt the plaintext with the authentication tag
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    # Combine salt, IV, AAD, ciphertext, and tag
    encrypted_data = base64.b64encode(salt + iv + aad + ciphertext + encryptor.tag)

    return encrypted_data


def encrypt_aes(plaintext, password): # FOR ENCRYPTING TEXT ONLY

    
    # Generate a random salt (32 bytes for extra entropy)
    salt = os.urandom(32)  # 256-bit salt

    # Derive a strong 256-bit key
    key, _ = derive_key_from_password(password, salt)

    # Generate a 12-byte IV (Nonce) as required by AES-GCM
    iv = os.urandom(12)  # 12-byte IV (standard for AES-GCM)

    # Create AES-GCM cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())

    # Generate a random AAD (Associated Data)
    aad = os.urandom(32)  # 32 bytes of random associated data

    # Encrypt the plaintext with the authentication tag
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    # Combine salt, IV, AAD, ciphertext, and tag
    encrypted_data = base64.b64encode(salt + iv + aad + ciphertext + encryptor.tag)

    return encrypted_data.decode()

def decrypt_aes(encrypted_data, password): # FOR DECRYPYING ANYTHING
    # Decode from Base64
    encrypted_data = base64.b64decode(encrypted_data)

    # Extract Salt (32 bytes), IV (12 bytes), AAD (32 bytes), Ciphertext, and Tag
    salt = encrypted_data[:32]  # 32-byte salt
    iv = encrypted_data[32:44]  # 12-byte IV
    aad = encrypted_data[44:76]  # 32-byte AAD
    ciphertext = encrypted_data[76:-16]  # Ciphertext
    tag = encrypted_data[-16:]  # 16-byte Authentication Tag

    # Derive the key using the same salt
    key, _ = derive_key_from_password(password, salt)

    # Create cipher object
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(aad)

    # Decrypt and verify authentication tag
    decrypted_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    decrypted_string = decrypted_plaintext.decode('utf-8')
    return decrypted_plaintext.decode('utf-8')

def overwrite_vault(filepath, content, password):
    # contents is a list right now
    json_string = json.dumps(content)
    encrypted_blob = encrypt_files_aes(json_string, password)
    with open(filepath, 'wb') as f:
            f.write(encrypted_blob)
    print(f"\nFile {filepath} has been encrypted and overwritten.")

# Original tool built by StarcrestMC - https://github.com/starcrestmc/Encryptor-v6

def vault_manager(switchcase, ciphertext=None, ref=None, master=None): # 0 is to unlock the master vault, 1 is get your password from reference, 2 is clear all
    if switchcase == 0:
        with open('Vault/master.json', 'rb') as encrypted_master:
            ciphertext = encrypted_master.read()
            password = getpass.getpass("Enter your Master password: ")
            master_vault = decrypt_aes(ciphertext, password)
            ciphertext = ""
            master_list = json.loads(master_vault) # 'loads' is not a typo, loads = string or bytes
            return master_list

    elif switchcase == 1:
        try:
            print(master)
        except:
            print("Please unlock Master Vault first")
            return
        password = master[int(ref)]
        try:
            named_vault = decrypt_aes(ciphertext, password)
        except:
            print("Incorrect Password")
            return
        return named_vault
    
    elif switchcase == 2: # clear all 
        master = ""
        named_vault = ""
        ciphertext = ""
        password = ""


###################################################################################################################
def message_blur(master):
    
    name = input("\nPlease Enter the name of the Person who\'s list to use for this session:\n") # do this for enc and decryption
    with open(f'Vault/{name}.json', 'rb') as encrypted_named:
        ciphertext = encrypted_named.read() # set ciphertext to the encrypted list
        ref = input(f'Please Enter Your Reference Number for {name}: ')
        named_vault = vault_manager(1, ciphertext, int(ref), master) # vault manager handles encryption, case 1 is encryption
        sharedvault = json.loads(named_vault)
        # Now you have unlocked the vault to reference passwords between chosen person

    reference_number = secrets.randbelow(1029) # Get a secure random number | we append this number to the end
    plaintext = input("What is your message? \n")
    password = sharedvault[int(reference_number)]
    #print(f'Password: {password}')
    encrypted_msg = encrypt_aes(plaintext, password)
    sharedvault.pop(int(reference_number)) # delete the password so it cant be reused also pop doesn't need assignment as it updates the variable its being used on
    # print(str(sharedvault))
    t.sleep(5)
    post_pop_length = len(sharedvault) # also append this which is length of list after removal
    encrypted_msg = f'{encrypted_msg}:{reference_number}_{post_pop_length}'
    print(f'\nYour List is now {post_pop_length} entries long\n\n\n')

    private_key_location = "PGPKeys/private.asc" # Personal private PGP key location
    pub = input("Friends's public key name? (without .asc)\n")
    full_file = f'{pub}.asc' #Receivers key
    friend_key_location = "PGPKeys/" + str(full_file)
    msg = encrypted_msg
    run_pgp = PGPmsg.enc(private_key_location,friend_key_location,msg)
    #print(f'Your Message:\n {run_pgp}')

    message  = hide_text(str(run_pgp))

    print(f'Encoded: >{message}<')

    password = master[int(ref)]
    
    overwrite_vault(f'Vault/{name}.json', sharedvault, password)
    password = ""
    sharedvault = ""
    main_menu()

##################################################################################################################
def message_unblur(master):
    name = input("\nPlease Enter the name of the Person who\'s list to use for this session:\n")

    with open(f'Vault/{name}.json', 'rb') as encrypted_named:
        ciphertext = encrypted_named.read() # set ciphertext to the encrypted list
        ref = getpass.getpass("Please Enter Your Reference Number for {name}: ")
        named_vault = vault_manager(1, ciphertext, ref, master) # vault manager handles encryption, case 1 is encryption
        sharedvault = json.loads(named_vault)
        # Now you have unlocked the vault to reference passwords between chosen person
        
    ciphertext = input("\nPlease enter your ciphertext:\n")
    ciphertext = show_text(ciphertext)
    private_key_location = "PGPKeys/private.asc" # Personal private PGP key location

    senders_key = input("Name of sender's public key for verification (without .asc)?\n ")
    full_file = f'{senders_key}.asc' #senders key
    complete_path = "PGPKeys/" + str(full_file)
    run = PGPmsg.dec(private_key_location,complete_path,ciphertext)
    decrypted_pgp = run[0]
    verified = run[1]
    #print("Decrypted message:\n", decrypted_pgp.message)
    print("Signature verified:", bool(verified))

    text_seperator_pass_1 = str(decrypted_pgp.message).split(":")
    ciphertext = text_seperator_pass_1[0] # Ciphertext here
    # print(str(ciphertext))
    metadata = text_seperator_pass_1[1]
    text_seperator_pass_2 = metadata.split("_")
    reference = text_seperator_pass_2[0] # Ref Num Here
    post_pop_length = text_seperator_pass_2[1] # Length after Popping here, check after popping

    password = sharedvault[int(reference)]
    decrypted_msg = decrypt_aes(ciphertext, password)
    sharedvault.pop(int(reference)) # delete the password so it cant be reused also pop doesn't need assignment as it updates the variable its being used on
    new_length = len(sharedvault)
    if int(new_length) != int(post_pop_length):
        print("Error, Password sync Mismatch")
        hashed = sha256(password.encode('utf-8')).hexdigest()
        print(f'Password Hash: {hashed} | Password Index {reference}')
        print("\nPlease Compare with Sender\n")

    print(f'Message:\n\n{decrypted_msg}')
    # friend should use list en/decoder tool to unlock and check what's at that position manually

    password = master[int(ref)]
    overwrite_vault(f'Vault/{name}.json', sharedvault, password)
    password = ""
    sharedvault = ""
    main_menu()
    
def master_vault_setup():
    shutil.copy('Vault/BLANK.json', 'Vault/Master.json') # make the master file
    print("\n\n\nGenerated master \n")
    list_generate('Master')
    print("\nList Generated\n\n\n")
    main_menu()
    
def friends_vault_generator():
    friendname = input("Please enter your friends name: ")
    shutil.copy('Vault/BLANK.json', f'Vault/{friendname}.json')
    list_generate(f'{friendname}')
    print("Share file with your friend and tell them to rename it to your name (keep a copy for later)")
    main_menu()

def encrypt_vault():
    def encrypt_existing_vault(filepath, password):
        # 1. Read the current readable JSON content
        with open(filepath, 'r') as f:
            original_content = f.read()

        # 2. Encrypt the content using your function
        # This turns the text into the Base64 bytes blob
        encrypted_blob = encrypt_files_aes(original_content, password)

        # 3. Overwrite the file with the encrypted version
        # We use 'wb' because your function returns bytes
        with open(filepath, 'wb') as f:
            f.write(encrypted_blob)
            
        print(f"File {filepath} has been encrypted and overwritten.")

    # Usage
    ask_type = input("Are you encrypting a [F]riend\'s vault or the [M]aster vault?\n")
    
    if ask_type.lower() == "f":
        master_vault_status = input("Is the master vault currently Encrypted? [Y]es/[N]o: ")
        if master_vault_status == "y":
            master = vault_manager(0, ciphertext, ref)
            # Unlock the Master to do any further operations
        else:    
            file_name = input("Please Enter File name to Encrypt without .json\n")
            password_index = input("\nPlease Enter Password Number from Master.json to use\n    (Make sure to Note this down!)\n")
            with open('Vault/master.json', 'rb') as f:
                master = f.read()
            data = json.loads(master)
            password = data[int(password_index)]
            encrypt_existing_vault(f'Vault/{file_name}.json', f'{password}')
            password = ""
        main_menu()
        
    elif ask_type.lower() == "m":
        
        password = input("\nPlease Enter Password to encrypt master.json\n    (Make sure to Note this down!)\n")
        with open('Vault/master.json', 'rb') as f:
            master = f.read()
        data = json.loads(master)
        encrypt_existing_vault(f'Vault/Master.json', f'{password}')
        password = ""
        main_menu()
        
def main_menu():
    print('\n\n- Welcome to The Encrypter! -\n')
    print('(1) Generate Your Master File')
    print('(2) Generate a Friends Shared File')
    print('(3) Encrypt all Vault Files')
    print('(4) Encrypt Text')
    print('(5) Decrypt Text')
    start_menu_choice = input('\n > ')

    if start_menu_choice == "1":
        master_vault_setup()
    elif start_menu_choice == "2":
        friends_vault_generator()
    elif start_menu_choice == "3":
        encrypt_vault()
    elif start_menu_choice == "4":
        master = vault_manager(0)
        # Unlock the Master Vault to do any further operations
        #print(len(master)) if 1028 then master was successfully decoded and retrieved
        message_blur(master)
    elif start_menu_choice == "5":
        master = vault_manager(0)
        # Unlock the Master to do any further operations
        message_unblur(master)
print("-- [ This tool was made by StarcrestMC - https://github.com/starcrestmc/Encryptor-v6 ] --")
main_menu()

# Original tool built by StarcrestMC - https://github.com/starcrestmc/Encryptor-v6
