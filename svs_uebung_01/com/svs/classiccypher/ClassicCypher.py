'''
Created on 10.04.2013

@author: Frank Schmidt
'''
import re
class Main(object):
    def __init__(self):
        crypto = '''
-the- does increased security provide comfort to paranoid people? Or does security provide some very basic protections 
that we are naive to believe that we don't need? During this time when the Internet provides essential communication between 
tens of millions of people and is being increasingly used as a tool for commerce, security becomes a tremendously important 
issue to deal with. There are many aspects to security and many applications, ranging from secure commerce and payments to 
private communications and protecting passwords. One essential aspect for secure communications is that of cryptography, 
which is the focus of this chapter. But it is important to note that while cryptography is necessary for secure communications, 
it is not by itself sufficient. The reader is advised, then, that the topics covered in this chapter only describe the first 
of many steps necessary for better security in any number of situations. 
This paper has two major purposes. The first is to define some of the terms and concepts behind basic cryptographic methods, 
and to offer a way to compare the myriad cryptographic schemes in use today. The second is to provide some real examples of 
cryptography in use today. I would like to say at the outset that this paper is very focused on terms, concepts, and schemes 
in current use and is not a treatise of the whole field. No mention is made here about pre-computerized crypto schemes, the 
difference between a substitution and transposition cipher, cryptanalysis, or other history. Interested readers should check 
out some of the books in the references section below for detailed and interesting! background information.'''

        #print(crypto.lower())
        key, encoded = encode(crypto.lower())
        #print(encoded)
        #print("Real key:")
        #printKey(key)
        #print("Calculated key: ")
        decodedKey = decode(encoded)
        #print(decodedKey)
        decodedText = decodeText(encoded, decodedKey)
        #print(decodedText)

        for s in commonTripples:
            key = searchDictionary(decodedText, s)
            #print(key)
            if not key:
                continue
            temp = {v: k for k, v in decodedKey.items()}
            for c in [c for c in list(s) if c in temp]:
                if c == key[1] and not str.isupper(decodedKey[key[0]]) and c.upper() not in temp.keys():
                    decodedKey[temp[key[0]]] = key[1].upper()
                elif c.upper() not in temp:
                    decodedKey[temp[c]] = c.upper()

        print(decodedKey)

        print(decodeText(encoded, decodedKey))




from collections import Counter
import random
letterFrequency = {'a':8.167, 'b':1.492, 'c':2.782, 'd':4.253, 'e':12.702, 'f':2.228, 'g':2.015, 'h':6.094, 'i':6.966, 'j':0.153,
                     'k':0.772, 'l':4.025, 'm':2.406, 'n':6.749, 'o':7.507, 'p':1.929, 'q':0.095, 'r':5.987, 's':6.327, 't':9.056,
                     'u':2.758, 'v':0.978, 'w':2.360, 'x':0.150, 'y':1.974, 'z':0.074, ' ': 18.000 }

commonPairs = ['th', 'ea', 'of', 'to', 'in', 'it', 'is', 'be', 'as', 'at', 'so', 'we', 'he', 'by', 'or', 'on', 'do', 'if', 'me', 'my', 'up']
commonTripples = ['the', 'est', 'for', 'and', 'his', 'ent', 'tha']
commonRepetitions = ['ss', 'ee', 'tt', 'ff', 'll', 'mm', 'oo']

def decode(text):
    charCount = Counter(text)
    #print("Letter Freq in encoded text: ")
    #print(charCount)
    # we assume that there are only lower case letters encoded in the sequence
    for x in [x for x in charCount.keys() if not x in letterFrequency]:
        charCount.pop(x)
    sortedFreq = sorted(letterFrequency, key = letterFrequency.get, reverse = True)
    sortedCharCount = sorted(charCount, key = charCount.get, reverse = True)
    key = dict(zip(sortedCharCount, sortedFreq))

    return key

def encode(text):
    keys = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', ' ']
    values = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', ' ']

    # generate a random key
    random.shuffle(values)
    key = dict(zip(keys, values));

    t = list(text)

    for i in range(len(t)):
        if(t[i] in key):
            t[i] = key[t[i]];

    return (key, ''.join(t));

def decodeText(text, key):
    textAsList = list(text)
    for i in range(len(textAsList)):
        if textAsList[i] in key:
            textAsList[i] = key[textAsList[i]]

    return ''.join(textAsList)

def searchDictionary(text, word):
    pattern = ""
    for i in range(len(word) - 1):
        pattern += "" + word[0:i] + "([a-z])" + word[i + 1:len(word)] + "|"
    pattern += "" + word[0:len(word) - 1] + "([a-z])" + word[len(word):len(word)] + ""

    m = re.search(pattern, text)
    if not m:
        return
    for i in [i for i in range(len(word)) if i >= 1 and m.group(i)]:
        return (m.group(i), word[i - 1])
    return

def printKey(key):
    keylist = sorted(key.keys())
    for k in keylist:
        print("(%s: %s), " % (k, key[k]), end = "")

    print('')

if __name__ == '__main__':
    instance = Main()

