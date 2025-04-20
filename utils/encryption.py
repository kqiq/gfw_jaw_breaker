"""
Encryption utilities for the VPN service.
"""
import asyncio
import os
import base64
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# AES block size in bytes
AES_BLOCK_SIZE = 16

async def generate_key(method: str, password: Optional[str] = None) -> bytes:
    """
    Generate an encryption key based on the encryption method.
    
    Args:
        method: Encryption method (e.g., 'aes-256-gcm')
        password: Optional password to derive key from
        
    Returns:
        Encryption key as bytes
    """
    if password:
        # Derive key from password (this is a simple implementation)
        # In production, use a proper key derivation function like PBKDF2
        import hashlib
        if 'aes-256' in method:
            return hashlib.sha256(password.encode()).digest()
        elif 'aes-128' in method:
            return hashlib.md5(password.encode()).digest()
    
    # Generate random key based on method
    if 'aes-256' in method:
        return get_random_bytes(32)  # 256 bits = 32 bytes
    elif 'aes-128' in method:
        return get_random_bytes(16)  # 128 bits = 16 bytes
    else:
        # Default to AES-256
        return get_random_bytes(32)

async def encrypt_data(data: bytes, method: str, key: Optional[bytes] = None, 
                      password: Optional[str] = None) -> bytes:
    """
    Encrypt data using the specified encryption method.
    
    Args:
        data: Data to encrypt
        method: Encryption method (e.g., 'aes-256-gcm')
        key: Optional encryption key
        password: Optional password to derive key from
        
    Returns:
        Encrypted data
    """
    if not key:
        key = await generate_key(method, password)
    
    if 'aes' in method.lower():
        iv = get_random_bytes(AES_BLOCK_SIZE)
        
        if 'gcm' in method.lower():
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            # Format: IV + Tag + Ciphertext
            return iv + tag + ciphertext
        else:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(pad(data, AES_BLOCK_SIZE))
            # Format: IV + Ciphertext
            return iv + ciphertext
    
    # Fallback to simple XOR (insecure, just for demonstration)
    xor_key = key[:1] * len(data) if key else b'\x00' * len(data)
    return bytes([data[i] ^ xor_key[i] for i in range(len(data))])

async def decrypt_data(data: bytes, method: str, key: Optional[bytes] = None,
                      password: Optional[str] = None) -> bytes:
    """
    Decrypt data using the specified encryption method.
    
    Args:
        data: Data to decrypt
        method: Encryption method (e.g., 'aes-256-gcm')
        key: Optional encryption key
        password: Optional password to derive key from
        
    Returns:
        Decrypted data
    """
    if not key:
        key = await generate_key(method, password)
    
    if 'aes' in method.lower():
        iv = data[:AES_BLOCK_SIZE]
        
        if 'gcm' in method.lower():
            tag = data[AES_BLOCK_SIZE:AES_BLOCK_SIZE+16]  # GCM tag is 16 bytes
            ciphertext = data[AES_BLOCK_SIZE+16:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            return cipher.decrypt_and_verify(ciphertext, tag)
        else:
            ciphertext = data[AES_BLOCK_SIZE:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ciphertext), AES_BLOCK_SIZE)
    
    # Fallback to simple XOR (insecure, just for demonstration)
    xor_key = key[:1] * len(data) if key else b'\x00' * len(data)
    return bytes([data[i] ^ xor_key[i] for i in range(len(data))])

async def generate_dh_key_pair():
    """
    Generate a Diffie-Hellman key pair for secure key exchange.
    
    Returns:
        Tuple containing (private_key, public_key)
    """
    # This is a placeholder. In a real implementation, you would use a proper
    # cryptographic library for DH key exchange
    from cryptography.hazmat.primitives.asymmetric import dh
    from cryptography.hazmat.backends import default_backend
    
    # Generate parameters
    parameters = dh.generate_parameters(generator=2, key_size=2048, 
                                       backend=default_backend())
    
    # Generate private key
    private_key = parameters.generate_private_key()
    
    # Get public key
    public_key = private_key.public_key()
    
    return private_key, public_key 