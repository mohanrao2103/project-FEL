from key_loader import get_random_keys
from encryption import encrypt_data
from decryption import decrypt_data
from digital_signature import generate_signature, verify_signature
import csv
import random
import hashlib
from quantum_generator import get_random_sequence_from_csv 



methods, hash_value = get_random_sequence_from_csv()


# def get_random_sequence_from_csv(csv_file='sequence.csv'):
#     """Get a random encryption sequence from the CSV file."""
#     sequences = []
    
#     with open(csv_file, 'r', newline='') as file:
#         reader = csv.reader(file)
#         next(reader)  # Skip header row
#         for row in reader:
#             if len(row) >= 2:  # Ensure row has sequence and hash
#                 sequence = row[0].strip('"')  # Remove quotes
#                 hash_value = row[1]
#                 sequences.append((sequence, hash_value))
    
#     if not sequences:
#         raise ValueError("No sequences found in the CSV file")
    
#     # Select a random sequence
#     selected = random.choice(sequences)
#     sequence_str, hash_value = selected
    
#     # Convert the sequence string to a list of methods
#     methods = [method.strip() for method in sequence_str.split(',')]
    
#     return methods, hash_value



def main():
    # Get randomly selected keys
    key_aes, key_des, key_tdes, private_key_rsa, public_key_rsa, private_key_ecc, public_key_ecc = get_random_keys()
    
    # Show the selected keys (truncated for readability)
    print(f"Selected AES Key: {key_aes.hex()[:20]}...")
    print(f"Selected DES Key: {key_des.hex()}")
    print(f"Selected Triple DES Key: {key_tdes.hex()[:20]}...")
    print(f"Selected RSA Private Key: {private_key_rsa.export_key().hex()[:20]}...")
    print(f"Selected RSA Public Key: {public_key_rsa.export_key().hex()[:20]}...")
    
    # For ECC keys, we'll just print the key details
    print(f"Selected ECC Private Key: {private_key_ecc.d}")
    print(f"Selected ECC Public Key: (x={public_key_ecc.pointQ.x}, y={public_key_ecc.pointQ.y})")
    
    # Original data
    data = "Hello, Multi-layer encryption!"
    print(f"\nOriginal Data: {data}")
    
    # Get a random encryption sequence from the CSV file
    methods, sequence_hash = get_random_sequence_from_csv()
    print(f"\nSelected Encryption Sequence: {' -> '.join(methods)}")
    print(f"Sequence Hash: {sequence_hash}")
    
    # Generate digital signature for the original data
    signature = generate_signature(data, private_key_rsa)
    print(f"Generated digital signature: {signature[:20]}...")
    
    # Encrypt
    ivs, encrypted_data, tags = encrypt_data(data, methods, key_aes, key_des, key_tdes, public_key_rsa, public_key_ecc)
    print(f"\nFinal Encrypted Data: {encrypted_data}")
    
    # In a real system, you would transmit:
    # 1. The encrypted data
    # 2. The IVs
    # 3. The tags (if any)
    # 4. The sequence hash (NOT the actual sequence for security)
    # 5. The digital signature
    print("\n--- Transmission Data ---")
    print(f"Encrypted Data: {encrypted_data}")
    print(f"IVs: {ivs}")
    print(f"Tags: {tags}")
    print(f"Sequence Hash: {sequence_hash}")
    print(f"Digital Signature: {signature[:20]}...")
    
    # Decrypt (using the hash to look up the sequence)
    decrypted_data = decrypt_data(ivs, encrypted_data, tags, methods, key_aes, key_des, key_tdes, private_key_rsa, private_key_ecc)
    print(f"\nFinal Decrypted Data: {decrypted_data}")
    
    # Verify digital signature
    is_valid = verify_signature(decrypted_data, signature, public_key_rsa)
    if is_valid:
        print("\nDigital signature verified: Data integrity confirmed")
    else:
        print("\nWARNING: Digital signature verification failed. The data may have been tampered with.")
    
    # Verify decryption success
    print(f"\nDecryption {'Successful' if data == decrypted_data else 'Failed'}!")
    
    # # Demonstrate tampering detection
    # print("\n--- Demonstrating Tampering Detection ---")
    # # Simulate tampering by modifying the signature
    # tampered_signature = signature[:-5] + "XXXXX"
    # is_valid = verify_signature(decrypted_data, tampered_signature, public_key_rsa)
    # if is_valid:
    #     print("ERROR: Tampered data was not detected!")
    # else:
    #     print("SUCCESS: Tampering was successfully detected!")

if __name__ == "__main__":
    main()