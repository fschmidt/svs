from aifc import Error
from optparse import OptionParser
import asyncore
import hashlib
import smtpd
import struct
'''
Created on 19.06.2013

@author: Frank Schmidt und Marcus Fabarius
'''
PRIME = 977
BASE = 777

class SecretSMTPServer(smtpd.SMTPServer):

    def __init__(self, localaddr, remoteaddr, secret):
        print "Running fake smtp server"
        smtpd.SMTPServer.__init__(self, localaddr, remoteaddr)
        self.secret = secret

    def process_message(self, peer, mailfrom, rcpttos, data):
        print '####################################'
        print '##########INCOMING MESSAGE##########'
        print '####################################'
        print 'Receiving message from:', peer
        print 'Message addressed from:', mailfrom
        print 'Message addressed to  :', rcpttos
        print 'Message length        :', len(data)
        print '####################################'
        contents = data.split('\n')
        msg = contents[len(contents) - 1].decode('base64')
        if msg.startswith('PUB_KEY:'):
            B = int(msg[len('PUB_KEY:'):])
            a = int(self.secret)
            s = B ** a % PRIME
            print('SECRET:' + str(s))
            self.key = hashlib.sha256(str(s)).hexdigest()[:16]
        else:
            print(crypt(self.key, msg))

""" 
XTEA Block Encryption Algorithm

Author: Paul Chakravarti (paul_dot_chakravarti_at_gmail_dot_com)
License: Public Domain

This module provides a Python implementation of the XTEA block encryption
algorithm (http://www.cix.co.uk/~klockstone/xtea.pdf). 

The module implements the basic XTEA block encryption algortithm
(`xtea_encrypt`/`xtea_decrypt`) and also provides a higher level `crypt`
function which symmetrically encrypts/decrypts a variable length string using
XTEA in OFB mode as a key generator. The `crypt` function does not use
`xtea_decrypt` which is provided for completeness only (but can be used
to support other stream modes - eg CBC/CFB).

This module is intended to provide a simple 'privacy-grade' Python encryption
algorithm with no external dependencies. The implementation is relatively slow
and is best suited to small volumes of data. Note that the XTEA algorithm has
not been subjected to extensive analysis (though is believed to be relatively
secure - see http://en.wikipedia.org/wiki/XTEA). For applications requiring
'real' security please use a known and well tested algorithm/implementation.

The security of the algorithm is entirely based on quality (entropy) and
secrecy of the key. You should generate the key from a known random source and
exchange using a trusted mechanism. In addition, you should always use a random
IV to seed the key generator (the IV is not sensitive and does not need to be
exchanged securely)

    >>> import os
    >>> iv = 'ABCDEFGH'
    >>> z = crypt('0123456789012345','Hello There',iv)
    >>> z.encode('hex')
    'fe196d0a40d6c222b9eff3'
    >>> crypt('0123456789012345',z,iv)
    'Hello There'

"""


def crypt(key, data, iv = '\00\00\00\00\00\00\00\00', n = 32):
    """
        Encrypt/decrypt variable length string using XTEA cypher as
        key generator (OFB mode)
        * key = 128 bit (16 char) 
        * iv = 64 bit (8 char)
        * data = string (any length)

        >>> import os
        >>> key = os.urandom(16)
        >>> iv = os.urandom(8)
        >>> data = os.urandom(10000)
        >>> z = crypt(key,data,iv)
        >>> crypt(key,z,iv) == data
        True

    """
    def keygen(key, iv, n):
        while True:
            iv = xtea_encrypt(key, iv, n)
            for k in iv:
                yield ord(k)
    xor = [ chr(x ^ y) for (x, y) in zip(map(ord, data), keygen(key, iv, n)) ]
    return "".join(xor)

def xtea_encrypt(key, block, n = 32, endian = "!"):
    """
        Encrypt 64 bit data block using XTEA block cypher
        * key = 128 bit (16 char) 
        * block = 64 bit (8 char)
        * n = rounds (default 32)
        * endian = byte order (see 'struct' doc - default big/network) 

        >>> z = xtea_encrypt('0123456789012345','ABCDEFGH')
        >>> z.encode('hex')
        'b67c01662ff6964a'

        Only need to change byte order if sending/receiving from 
        alternative endian implementation 

        >>> z = xtea_encrypt('0123456789012345','ABCDEFGH',endian="<")
        >>> z.encode('hex')
        'ea0c3d7c1c22557f'

    """
    v0, v1 = struct.unpack(endian + "2L", block)
    k = struct.unpack(endian + "4L", key)
    sum, delta, mask = 0L, 0x9e3779b9L, 0xffffffffL
    for round in range(n):
        v0 = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
        sum = (sum + delta) & mask
        v1 = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
    return struct.pack(endian + "2L", v0, v1)

def xtea_decrypt(key, block, n = 32, endian = "!"):
    """
        Decrypt 64 bit data block using XTEA block cypher
        * key = 128 bit (16 char) 
        * block = 64 bit (8 char)
        * n = rounds (default 32)
        * endian = byte order (see 'struct' doc - default big/network) 

        >>> z = 'b67c01662ff6964a'.decode('hex')
        >>> xtea_decrypt('0123456789012345',z)
        'ABCDEFGH'

        Only need to change byte order if sending/receiving from 
        alternative endian implementation 

        >>> z = 'ea0c3d7c1c22557f'.decode('hex')
        >>> xtea_decrypt('0123456789012345',z,endian="<")
        'ABCDEFGH'

    """
    v0, v1 = struct.unpack(endian + "2L", block)
    k = struct.unpack(endian + "4L", key)
    delta, mask = 0x9e3779b9L, 0xffffffffL
    sum = (delta * n) & mask
    for round in range(n):
        v1 = (v1 - (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum >> 11 & 3]))) & mask
        sum = (sum - delta) & mask
        v0 = (v0 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]))) & mask
    return struct.pack(endian + "2L", v0, v1)

if __name__ == "__main__":
    print("> started")

    parser = OptionParser()
    parser.add_option("-p", dest = "port", default = False)
    parser.add_option("--secret", dest = "secret", default = False)
    (options, args) = parser.parse_args()

    #   start the server
    server = SecretSMTPServer(('127.0.0.1', int(options.port)), None, options.secret)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        server.close()

    print("> finished")


