import nacl.secret
import nacl.utils



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

    
        
