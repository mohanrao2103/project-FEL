import csv
import base64
import random
import os
from Crypto.PublicKey import RSA, ECC

def load_keys_from_csv(enc_filename='encryption_keys.csv', dec_filename='decryption_keys.csv'):
    encryption_key_sets = []
    decryption_key_sets = []
    
    # Load encryption keys
    with open(enc_filename, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for i, row in enumerate(reader):
            # Skip the header row (already handled by DictReader)
            encryption_key_sets.append(row)
    
    # Load decryption keys
    with open(dec_filename, 'r', newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for i, row in enumerate(reader):
            # Skip the header row (already handled by DictReader)
            decryption_key_sets.append(row)
    
    return encryption_key_sets, decryption_key_sets

def select_random_key_set(encryption_key_sets, decryption_key_sets):
    # Make sure we have key sets to choose from
    if not encryption_key_sets or not decryption_key_sets:
        raise ValueError("No key sets available")
    
    # Select a random index (same for both sets to ensure matching keys)
    random_index = random.randint(0, min(len(encryption_key_sets), len(decryption_key_sets)) - 1)
    
    return encryption_key_sets[random_index], decryption_key_sets[random_index]

def prepare_keys(enc_key_set, dec_key_set):
    # Decode base64 keys
    key_aes = base64.b64decode(enc_key_set['aes_key'])
    key_des = base64.b64decode(enc_key_set['des_key'])
    key_tdes = base64.b64decode(enc_key_set['tdes_key'])
    
    # Import RSA keys
    private_key_rsa_data = base64.b64decode(dec_key_set['private_key_rsa'])
    private_key_rsa = RSA.import_key(private_key_rsa_data)
    
    public_key_rsa_data = base64.b64decode(enc_key_set['public_key_rsa'])
    public_key_rsa = RSA.import_key(public_key_rsa_data)
    
    # Import ECC keys
    private_key_ecc_d = int(base64.b64decode(dec_key_set['private_key_ecc']).decode())
    
    public_key_ecc_data = base64.b64decode(enc_key_set['public_key_ecc']).decode().split('|')
    public_key_ecc_x = int(public_key_ecc_data[0])
    public_key_ecc_y = int(public_key_ecc_data[1])
    
    # Construct ECC keys
    private_key_ecc = ECC.construct(curve='P-256', d=private_key_ecc_d)
    public_key_ecc = ECC.construct(curve='P-256', point_x=public_key_ecc_x, point_y=public_key_ecc_y)
    
    return key_aes, key_des, key_tdes, private_key_rsa, public_key_rsa, private_key_ecc, public_key_ecc

def get_random_keys():
    # Check if keys CSV exists, if not generate them
    enc_filename = 'encryption_keys.csv'
    dec_filename = 'decryption_keys.csv'
    
    if not os.path.exists(enc_filename) or not os.path.exists(dec_filename):
        print(f"Keys files not found. Generating new keys...")
        from generate_keys import generate_keys_csv
        generate_keys_csv(num_sets=20, enc_filename=enc_filename, dec_filename=dec_filename)
    
    # Load keys from CSV files
    encryption_key_sets, decryption_key_sets = load_keys_from_csv(enc_filename, dec_filename)
    print(f"Loaded {len(encryption_key_sets)} encryption key sets and {len(decryption_key_sets)} decryption key sets")
    
    # Randomly select a key set
    enc_key_set, dec_key_set = select_random_key_set(encryption_key_sets, decryption_key_sets)
    print(f"\nRandomly selected key set")
    
    # Prepare the keys for use
    return prepare_keys(enc_key_set, dec_key_set)