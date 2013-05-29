from PIL import Image
import struct
import itertools
'''
Created on 24.05.2013

@author: Frank Schmidt
'''
def disguise(imagePath, dataPath):
    image = Image.open(imagePath)
    data = open(dataPath).read()
    payload = addHeader(data)
    bits = asBits(payload)
    image_data = image.getdata()


    length = readHeader(toString(bits, 0, 4))
    print(length)
    print("toString(bits): " + toString(bits, 4, int(length) + 4))

    print(bits)
    newdata = hideBitsInImageData(bits, image_data)

    result = Image.new('RGBA', image_data.size)
    result.putdata(newdata)
    result.save('result.jpg')

def reveal(imagePath):
    image = Image.open(imagePath)
    bits = []
    for p in image.getdata():
        bits.append(p[0] & 1)
        bits.append(p[1] & 1)
        bits.append(p[2] & 1)

    length = readHeader(toString(bits, 0, 4))
    test = []
    for b in range(0, 20, 1):
        test.append(bits[b])
    print(test)
    print(length)


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
        r = (image_data[j][0] & ~1) | bits[i]
        g = (image_data[j][1] & ~1) | bits[i + 1]
        b = (image_data[j][2] & ~1) | bits[i + 2]
        newdata[j] = (r, g, b)

    return newdata

if __name__ == "__main__":
    disguise('Lighthouse.jpg', 'test.txt')
    reveal('result.jpg')
