#!/usr/bin/env python3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from typing import Callable
import pdb
import os

class CryptoProvider:

    _GENERATOR=2
    _KEYSIZE=2048

    def __init__(self, getkey: Callable[[],str]):
        self._parameter = dh.generate_parameters(generator=self._GENERATOR, key_size=self._KEYSIZE)
        self._getkey = getkey
        self.reset()

    def _erase_key(self):
        self._session_key_derivated = None
        self._session_key = None
        self.established = False

    def _clean_cache(self):
        self._encrypt_cache = None
        self._decrypt_cache = None

    def reset(self):
        self._nonce = None
        self._clean_cache()
        self._erase_key()
        self.rekey()

    def rekey(self):
        self._private_key = self._parameter.generate_private_key()

    def setup(self,prime_bytes: bytes):
        prime = int.from_bytes(prime_bytes,byteorder="big")
        pn = dh.DHParameterNumbers(prime, self._GENERATOR)
        self._parameter = pn.parameters()
        self._private_key = self._parameter.generate_private_key()

    def nonce(self) -> bytes:
        if self._nonce is None:
            self._nonce = os.urandom(4)
        return self._nonce

    def checknonce(self,nonce: bytes) -> bool:
        if isinstance(nonce,int):
            nonce = nonce.to_bytes(4,byteorder="big")
        return nonce==self._nonce

    def pubkey(self) -> bytes:
        pkey = self._private_key.public_key()
        return self._encode_large_int(pkey.public_numbers().y)
    def prime(self) -> bytes:
        numbers = self._parameter.parameter_numbers()
        return self._encode_large_int(numbers.p)

    def _encode_large_int(self,n: int) -> bytes:
        v = n
        result = b''
        while v:
            curr = v & 0xFF
            result = curr.to_bytes(1,byteorder="big") + result
            v >>= 8
        return result

    def setremote(self,y_bytes: bytes,delay=False):
        y = int.from_bytes(y_bytes,byteorder="big")
        npara = self._parameter.parameter_numbers()
        npub = dh.DHPublicNumbers(y,npara)
        pubkey = npub.public_key()
        self._session_key = self._private_key.exchange(pubkey)
        self._session_key_derivated = self._sha256(self._session_key)
        self.established = None if delay else True

    def hmac(self,items: list) -> bytes:
        secret = self._getkey().encode()
        psk = self._sha256(secret)
        message = b''
        for item in items:
            data = self._encode_large_int(item) if isinstance(item,int) else item
            message = message + data
        return self._sha256(message+psk)

    def checkhmac(self,items: list, signature: bytes) -> bool:
        reference = self.hmac(items)
        return reference==signature


    def _sha256(self, message: bytes) -> bytes:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(message)
        return digest.finalize()

    def encrypt(self, data: bytes) -> bytes:
        nonce = self._encrypt_cache
        if nonce is None:
            nonce = os.urandom(12)
        cipher = AESGCM(self._session_key_derivated)
        cipher_text = cipher.encrypt(nonce,data,None)
        if self._encrypt_cache is None:
            cipher_text = nonce + cipher_text
        self._encrypt_cache = cipher_text[-12:]
        return cipher_text

    def decrypt(self, data: bytes) -> bytes:
        nonce = self._decrypt_cache
        if nonce is None:
            nonce = data[:12]
            data = data[12:]
        self._decrypt_cache = data[-12:]
        cipher = AESGCM(self._session_key_derivated)
        plain_text = cipher.decrypt(nonce,data,None)
        return plain_text
