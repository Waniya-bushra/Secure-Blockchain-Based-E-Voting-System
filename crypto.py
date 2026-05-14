import hmac
import hashlib
import os
import json
import random
import string
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# ─────────────────────────────────────────────
# Fernet symmetric key (for log HMAC secret)
# ─────────────────────────────────────────────
KEY_FILE       = 'secret.key'
RSA_PRIV_FILE  = 'rsa_private.pem'
RSA_PUB_FILE   = 'rsa_public.pem'


def get_fernet_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    return key


fernet = Fernet(get_fernet_key())


def encrypt_data(text):
    return fernet.encrypt(text.encode()).decode()


def decrypt_data(token):
    return fernet.decrypt(token.encode()).decode()


# ─────────────────────────────────────────────
# Vote token + hash helpers
# ─────────────────────────────────────────────
def generate_vote_token(student_id, society_id):
    secret = os.urandom(32).hex()
    data   = f"{student_id}:{society_id}:{secret}"
    return hashlib.sha256(data.encode()).hexdigest()


def hash_vote(candidate, society, token):
    data = f"{candidate}:{society}:{token}"
    return hashlib.sha256(data.encode()).hexdigest()


# ─────────────────────────────────────────────
# Tamper-evident audit log HMAC
# ─────────────────────────────────────────────
def compute_log_hmac(log_entry, prev_hash):
    content = json.dumps(log_entry, sort_keys=True, default=str) + prev_hash
    secret  = get_fernet_key()
    return hmac.new(secret, content.encode(), hashlib.sha256).hexdigest()


# ─────────────────────────────────────────────
# OTP  (6-digit numeric code)
# ─────────────────────────────────────────────
def generate_otp():
    """Return a random 6-digit string."""
    return ''.join(random.choices(string.digits, k=6))


# ─────────────────────────────────────────────
# RSA key management
# ─────────────────────────────────────────────
def get_rsa_keys():
    """
    Load existing RSA keys from disk, or generate a new 2048-bit pair.
    Returns (private_key_object, public_key_object).
    """
    if os.path.exists(RSA_PRIV_FILE) and os.path.exists(RSA_PUB_FILE):
        with open(RSA_PRIV_FILE, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        with open(RSA_PUB_FILE, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )
        return private_key, public_key

    # Generate new pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Save private key
    with open(RSA_PRIV_FILE, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open(RSA_PUB_FILE, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key


def sign_results(results_json_str):
    """
    Sign the JSON string of election results with the RSA private key.
    Returns the hex-encoded signature.
    """
    private_key, _ = get_rsa_keys()
    signature = private_key.sign(
        results_json_str.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()


def verify_results(results_json_str, signature_hex):
    """
    Verify election results against the stored RSA public key.
    Returns True if valid, False otherwise.
    """
    try:
        _, public_key = get_rsa_keys()
        public_key.verify(
            bytes.fromhex(signature_hex),
            results_json_str.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def get_public_key_pem():
    """Return the PEM string of the RSA public key (safe to show anyone)."""
    _, public_key = get_rsa_keys()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


# ─────────────────────────────────────────────
# Blockchain helpers
# ─────────────────────────────────────────────
def compute_block_hash(index, society_id, candidate, vote_token, timestamp, prev_hash):
    """SHA-256 hash of all block fields combined."""
    block_string = json.dumps({
        'index':      index,
        'society_id': society_id,
        'candidate':  candidate,
        'vote_token': vote_token,
        'timestamp':  timestamp,
        'prev_hash':  prev_hash
    }, sort_keys=True)
    return hashlib.sha256(block_string.encode()).hexdigest()


def verify_blockchain(blocks):
    """
    Walk every block and re-compute its hash.
    Returns (True, '') if chain is intact, or (False, reason) if broken.
    """
    for i, block in enumerate(blocks):
        recomputed = compute_block_hash(
            block.index,
            block.position,
            block.candidate,
            block.vote_token,
            block.timestamp,
            block.prev_hash
        )
        if recomputed != block.block_hash:
            return False, f"Block {block.index} hash mismatch — data may have been tampered!"
        if i > 0 and block.prev_hash != blocks[i - 1].block_hash:
            return False, f"Block {block.index} broken chain link!"
    return True, "Blockchain integrity verified ✅"