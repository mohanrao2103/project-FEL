import csv
import hashlib
import random
import time
from typing import Dict, Tuple, Optional
from sympy import mod_inverse, isprime
import logging

class ZKPAuthenticator:
    """Zero-Knowledge Proof Authentication System"""
    
    def __init__(self):
        self.test_modulo = 10007  # Prime number for modular arithmetic
        self.challenge_buffer = {}
        self.secret_keys = {}
        self.load_secret_keys()

    def load_secret_keys(self):
        """Load secret keys from the credentials.csv file."""
        try:
            with open('credentials.csv', 'r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    username = row['username']
                    secret_key = row['zkp_secret']
                    self.secret_keys[username] = secret_key
            logging.info("Secret keys loaded successfully from credentials.csv")
        except FileNotFoundError:
            logging.error("credentials.csv file not found. No secret keys loaded.")
        except Exception as e:
            logging.error(f"Error loading secret keys: {e}")

    def register_user(self, username: str) -> str:
        """Register a new user and generate their secret key."""
        if username in self.secret_keys:
            raise ValueError(f"User {username} is already registered.")
        secret_key = f"secret_{hash(username)}"
        self.secret_keys[username] = secret_key
        logging.info(f"User {username} registered with ZKP secret key: {secret_key}")
        return secret_key

    def generate_challenge(self, username: str):
        """Generate a challenge for the user."""
        if username not in self.secret_keys:
            logging.error(f"User {username} not found in secret_keys")
            return False, None, "User not registered"
        
         # Generate a random challenge type (0 to 6)
        challenge = random.randint(0, 6)
        self.challenge_buffer[username] = challenge
        logging.info(f"Generated challenge {challenge} for user {username}")
        return True, challenge, "Challenge generated successfully"

    def verify_response(self, username: str, response: str):
        """Verify the response to a challenge."""
        if username not in self.challenge_buffer:
            return False, "No challenge found for user"
        
        # Get the challenge and expected response
        challenge = self.challenge_buffer[username]
        secret_key = self.secret_keys[username]
        expected_response = self.get_expected_response(challenge, secret_key)

        # Compare the actual response with the expected response
        if response == expected_response:
            del self.challenge_buffer[username]  # Clear the challenge after successful verification
            return True, "Authentication successful"
        return False, "Authentication failed"
    
    def get_expected_response(self, challenge, secret_key):
        """Returns the expected response based on the challenge type."""
        if challenge == 0:
            return hex(random.randint(1, 100))
        elif challenge == 1:
            return hashlib.sha256(str(secret_key).encode()).hexdigest()
        elif challenge == 2:
            return str(pow(7, 13, self.test_modulo))
        elif challenge == 3:
            timestamp = int(time.time())
            return hashlib.sha256((str(secret_key) + str(timestamp)).encode()).hexdigest()
        elif challenge == 4:
            return str(mod_inverse(17, self.test_modulo))
        elif challenge == 5:
            return str(self.fibonacci(10))
        elif challenge == 6:
            return "Prime" if isprime(9973) else "Not Prime"
        return "Invalid"

@staticmethod
def fibonacci(n):
    """Returns the nth Fibonacci number."""
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a