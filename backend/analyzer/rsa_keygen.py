import random

def is_prime(num: int, test_count: int = 4) -> bool:
    """Miller-Rabin primality test."""
    if num <= 1: return False
    if num <= 3: return True
    if num % 2 == 0: return False
    
    r, s = 0, num - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    
    for _ in range(test_count):
        a = random.randrange(2, num - 1)
        x = pow(a, s, num)
        if x == 1 or x == num - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, num)
            if x == num - 1:
                break
        else:
            return False
    return True

def generate_prime(bits: int) -> int:
    """Generates an n-bit prime number."""
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1  # Ensure it is n-bit and odd
        if is_prime(p):
            return p

def mod_inverse(e: int, phi: int) -> int:
    """Extended Euclidean Algorithm to find the modular inverse."""
    def eea(a, b):
        if b == 0: return a, 1, 0
        gcd, x1, y1 = eea(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y
    _, x, _ = eea(e, phi)
    return x % phi

def generate_custom_rsa_keys(bits: int = 1024) -> dict:
    """
    Generates a custom RSA keypair from scratch.
    WARNING: For educational purposes only. Do not use in production.
    """
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Standard public exponent
    d = mod_inverse(e, phi)
    
    return {
        "public_key": {"e": str(e), "n": str(n)}, # Converted to strings to prevent
        "private_key": {"d": str(d), "p": str(p), "q": str(q)} # JSON overflow errors in FastAPI
    }