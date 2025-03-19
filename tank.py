import hashlib
import time
import random
from sympy import mod_inverse, isprime

test_modulo = 10007

class Tank:
    def __init__(self, tank_id):
        self.tank_id = tank_id
        self.secret_key = f"secret_{tank_id}"

    def respond_to_challenge(self, challenge):
        if challenge == 0:
            return hex(random.randint(1, 100))
        elif challenge == 1:
            return hashlib.sha256(str(self.secret_key).encode()).hexdigest()
        elif challenge == 2:
            return str(pow(7, 13, test_modulo))
        elif challenge == 3:
            timestamp = int(time.time())
            return hashlib.sha256((str(self.secret_key) + str(timestamp)).encode()).hexdigest()
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
