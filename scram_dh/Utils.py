import binascii
#import os
#import hmac
#import hashlib
import uuid
#from nacl.public import PrivateKey, Box
from nacl import pwhash, hash, secret, utils, encoding, bindings

class Utils(object):
    """
    Helper functions for SCRAM library
    """

    @staticmethod
    def sha256(data):
        """Returns SHA256 digest"""
        #return hashlib.sha256(data).digest()
        return hash.sha256(data, encoder=encoding.HexEncoder)

    @staticmethod
    def nonce(size):
        """Returns random HEX string of a given size"""
        #return binascii.hexlify(os.urandom(size))
        return encoding.HexEncoder.encode(utils.random(size))

    @staticmethod
    def key_generation(size):
        """Returns random non-ASCII characters, including null bytes, value of a given size"""
        #return os.urandom(size)
        return utils.random(size)

    @staticmethod
    def bitwise_xor(arg1, arg2):
        """Returns bitwise XOR"""
        value = [ord(a) ^ ord(b) for a,b in zip(arg1,arg2)]
        return ''.join(chr(x) for x in value)
    
    #http://pynacl.readthedocs.io/en/stable/hashing/
    #http://pynacl.readthedocs.io/en/stable/hashing/#additional-hashing-usages-for-blake2b
    #http://pynacl.readthedocs.io/en/stable/hashing/#key-derivation
    @staticmethod
    def hmac_generation(password, key):
        """Returns keyed-hash message authentication code given a message (password) and a secret key (key)"""
        #original
        #return hmac.new(password, key, digestmod=hashlib.sha256).digest()
        
        # nacl hash integrity check without key 
        #return hash.sha256(password, encoder=encoding.HexEncoder)

        # key limited to 64 byte
        key = key[:64]
        return hash.blake2b(password, key=key, encoder=encoding.HexEncoder)
        #return hash.blake2b(password, len(key), key=key, salt=b'', person=b'',encoder=encoding.HexEncoder)

        # derivation salt
        #derivation_salt = utils.random(16)
        #personalization = b'<DK usage>'
        #return hash.blake2b(password, len(key), key=key, salt=derivation_salt, person=personalization,encoder=encoding.HexEncoder)

        # auto generated key
        #auth_key = utils.random(size=64)
        #return hash.blake2b(password, key=auth_key, encoder=encoding.HexEncoder)
        #return hash.blake2b(password, len(auth_key), key=auth_key, salt=b'', person=b'',encoder=encoding.HexEncoder)


    #http://pynacl.readthedocs.io/en/stable/password_hashing/
    @staticmethod
    def pbkdf2_hmac(password, salt, ic):
        """Returns password-based key derivation function + hmac algorithm with SHA256 as hash function of hmac"""
        #original
        #return hashlib.pbkdf2_hmac('sha256', password, salt, ic)

        # Password hashing key derivation with argon2i
        salt2 = utils.random(pwhash.argon2i.SALTBYTES)
        ops = pwhash.argon2i.OPSLIMIT_SENSITIVE
        mem = pwhash.argon2i.MEMLIMIT_SENSITIVE
        #return pwhash.scrypt.kdf(secret.SecretBox.KEY_SIZE, password, utils.random(pwhash.argon2i.SALTBYTES*2))
        return pwhash.argon2i.kdf(secret.SecretBox.KEY_SIZE, password, salt[:16], opslimit=ops, memlimit=mem)        
        #return pwhash.argon2i.kdf(secret.SecretBox.KEY_SIZE, password, salt2, opslimit=ops, memlimit=mem)

    @staticmethod
    def generate_password():
        """Returns a random uuid4 password as string value"""
        return str(uuid.uuid4())