import hashlib
import random
import time
from sympy import mod_inverse, isprime

test_modulo = 10007  # Prime number for modular inverse calculation

class Commander:
    def __init__(self):
        # 5 pre-registered tanks with predefined secret keys
        self.tanks = {
            1: "secret_1",
            2: "secret_2",
            3: "secret_3",
            4: "secret_4",
            5: "secret_5"
        }
        self.challenge_buffer = {}  # Stores challenges until next issuance

    def send_challenges(self):
        """Sends challenges to all tanks and stores them in the buffer."""
        self.challenge_buffer.clear()  # Clear previous challenges
        log_messages = []
        for tank_id in self.tanks:
            challenge = random.randint(0, 6)
            self.challenge_buffer[tank_id] = challenge
            log_messages.append(f"🚀 Challenge {challenge} sent to Tank {tank_id}")
        return log_messages  # Return log messages for GUI updates

    def verify_response(self, tank_id, response):
        """Verifies the response from a tank."""
        if tank_id not in self.challenge_buffer:
            return False, f"❌ No challenge issued for Tank {tank_id}!"

        challenge = self.challenge_buffer[tank_id]
        expected_response = self.get_expected_response(challenge, self.tanks[tank_id])

        if response == expected_response:
            return True, f"✅ Tank {tank_id} authentication successful!"
        else:
            return False, f"❌ Authentication failed for Tank {tank_id}!"

    def get_expected_response(self, challenge, secret_key):
        """Returns the expected response based on the challenge type."""
        if challenge == 0:
            return hex(random.randint(1, 100))
        elif challenge == 1:
            return hashlib.sha256(str(secret_key).encode()).hexdigest()
        elif challenge == 2:
            return str(pow(7, 13, test_modulo))
        elif challenge == 3:
            timestamp = int(time.time())
            return hashlib.sha256((str(secret_key) + str(timestamp)).encode()).hexdigest()
        elif challenge == 4:
            return str(mod_inverse(17, test_modulo))
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
