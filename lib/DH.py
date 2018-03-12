import os
import binascii
import hashlib

class DHBadKeyException(Exception):
    """Wrong received key
    key should not be 1 or p-1 and the group order should be at least (P-1) / 2
    """
    pass

class DH(object):
    """ A Diffie Hellman implementation
    Constants:
    KEY_SIZE: size of random number
    P: group order
    G: group generator

    Attributes:
    __a: exponent
    """
    
    KEY_SIZE = 32
    
    #  group 16, 4096-bit
    P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF
    G = 2
    __a = None
    __public_key = None

    def __init__(self):
        """
        define random exponent
        """
        self.__a = int(binascii.hexlify(os.urandom(self.KEY_SIZE)), base=16)
        self.__public_key = pow(self.G, self.__a, self.P)
        

    def public_key(self):
        """
        generates shared secret g^a mod p
        """
        return self.__public_key

    def shared_secret(self, other_key):
        """
        calculate shared secret
        (g^b mod p)^a mod p
        """
        other_key = long(other_key, 16)
        if 2 <= other_key and other_key <= self.P - 2 and pow(other_key, (self.P - 1) / 2, self.P) == 1:
            return hashlib.sha256(str(pow(other_key, self.__a, self.P)).encode()).digest()

        raise DHBadKeyException