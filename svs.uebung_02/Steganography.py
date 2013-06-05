from PIL import Image
import struct
import itertools
from optparse import OptionParser
import hashlib
'''
Created on 24.05.2013

@author: Frank Schmidt und Marcus wollte auch genannt werden =)
'''
from aifc import Error

def disguise(macpwhash, pwhash, imagePath, dataPath, target):
    print('################################################################')
    print('##########################DISGUISE##############################')
    print('################################################################')

    image = Image.open(imagePath)
    data = open(dataPath).read()

    payload = addHeader(encrypt(pwhash, macpwhash + data))

    bits = asBits(payload)

    image_data = image.getdata()
    newdata = hideBitsInImageData(bits, image_data)

    result = Image.new(image.mode, image_data.size)
    result.putdata(newdata)
    result.save(target, image.format)
    return bits

def reveal(imagePath):
    print('################################################################')
    print('###########################REVEAL###############################')
    print('################################################################')
    image = Image.open(imagePath)
    image_data = image.getdata()
    hbits = []
    for i in range(32):
        hbits.append(image_data[i][0] & 1)
        hbits.append(image_data[i][1] & 1)
        hbits.append(image_data[i][2] & 1)

    length = readHeader(toString(hbits, 0, 4))

    bits = []
    for i in range(len(image_data)):
        if len(bits) >= (length + 4) * 8:
            break
        bits.append(image_data[i][0] & 1)
        if len(bits) >= (length + 4) * 8:
            break
        bits.append(image_data[i][1] & 1)
        if len(bits) >= (length + 4) * 8:
            break
        bits.append(image_data[i][2] & 1)

    return toString(bits, 4, length + 4)

def asBits(data):
    result = []
    for ch, shift in itertools.product(data, range(7, -1, -1)):
        result.append((ord(ch) >> shift) & 1)
    return result

def toString(listOfBits, start, length):
    chars = []
    for b in range(start, length):
        byte = listOfBits[b * 8:(b + 1) * 8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)

def addHeader(data):
    return '%s%s' % (struct.pack('=L', len(data)), data)

def readHeader(head):
    return struct.unpack('=L', head[0:4])[0]

def hideBitsInImageData(bits, image_data):
    newdata = list(image_data)
    for i in range(0, len(bits), 3):
        j = i / 3

        oldR = image_data[j][0]
        oldG = image_data[j][1]
        oldB = image_data[j][2]

        r = (oldR & ~1) | bits[i]

        if i + 1 >= len(bits):
            newdata[j] = (r, oldG, oldB)
            break

        g = (oldG & ~1) | bits[i + 1]

        if i + 2 >= len(bits):
            newdata[j] = (r, g, oldB)
            break

        b = (oldB & ~1) | bits[i + 2]

        if (r & 1) != bits[i] or (g & 1) != bits[i + 1] or (b & 1) != bits[i + 2]:
            raise Error('Bits not encoded correctly')

        newdata[j] = (r, g, b)

    return newdata

def encrypt(pwhash, text):
    key = pwhash[:16]
    result = crypt(key, text, 'ABCDEFGH')
    result.encode('hex')
    return result

def decrypt(pwhash, text):
    key = pwhash[:16]
    result = crypt(key, text, 'ABCDEFGH')

    return result

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

import struct

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
    parser = OptionParser()
    parser.add_option("-m", dest = "macpw", default = False)
    parser.add_option("-k", dest = "pw", default = False)
    (options, args) = parser.parse_args()
    if len(args) > 2 or len(args) < 1:
        raise Error('Illegal number of arguments: ' + str(len(args)))

    macpw = options.macpw
    pw = options.pw
    macpwhash = hashlib.sha256(macpw).hexdigest()
    pwhash = hashlib.sha256(pw).hexdigest()

    if len(args) == 1:
        s = reveal(args[0])
        s = decrypt(pwhash, s)
        if not s.startswith(macpwhash):
            raise Error("Wrong macpw")
        f = open(args[0].replace(args[0][-3:], 'txt'), 'w')
        f.write(s[len(macpwhash):])
        print('Output written to: ' + f.name)
    if len(args) == 2:
        tmp = disguise(macpwhash, pwhash, args[1], args[0], args[1] + '.ste')
        length = readHeader(toString(tmp, 0, 4))
        print(decrypt(pwhash, toString(tmp, 4, length + 4)))
