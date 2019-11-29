import nacl.secret
import nacl.utils
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


class Salsa:
    def __init__(self, key):
        self.nonce_size = nacl.secret.SecretBox.NONCE_SIZE
        self.key = key
        self.box = nacl.secret.SecretBox(key)

    def encrypt(self, message):
        nonce = nacl.utils.random(self.nonce_size)
        encrypted_message = self.box.encrypt(message, nonce)
        
        return encrypted_message[self.nonce_size:], encrypted_message[:self.nonce_size]

    def decrypt(self, ciphertext, nonce):
        return self.box.decrypt(ciphertext,nonce)

    
class Chacha:
    def __init__(self, key):
        self.nonce_size = 12
        self.key = key
        self.box = ChaCha20Poly1305(key)

    def encrypt(self, message):
        nonce = nacl.utils.random(self.nonce_size)
        encrypted = self.box.encrypt(nonce, message, None)
        return encrypted[:-16], encrypted[-16:], nonce

    def decrypt(self, ciphertext, tag, nonce):
        return self.box.decrypt(nonce, ciphertext + tag, None)