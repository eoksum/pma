#!/usr/bin/python3

import requests
import bcrypt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generateKeypair():
    private_key_obj = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    public_key_obj = private_key_obj.public_key()
    
    privateKey = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    
    publicKey = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    
    return (publicKey, privateKey)

def hashPassword(password):
    salt = bcrypt.gensalt()
    hpass = bcrypt.hashpw(password, salt)
    return hpass

def doLogin(user, pass):
    