
words = 'oxygen fun inner bachelor cherry pistol knife quarter grass act ceiling wrap another input style profit middle cake slight glance silk rookie caught parade'

message = """
this is to test encryption
"""

secret = "12345"

import hashlib
import nacl.secret
import nacl.utils
import base64
from nacl.public import PrivateKey, SealedBox

from mnemonic import Mnemonic
import binascii
hexlify = binascii.hexlify
mnemonic = Mnemonic()

message = message.strip()

def md5(txt):
    txt=txt.encode('utf8')
    m = hashlib.md5()
    m.update(txt)
    md5bin=m.digest()    
    return hexlify(md5bin)

def encrypt():        
    """
    secret is any size key
    words are bip39 words e.g. see https://iancoleman.io/bip39/#english

    if words not given then will take from the default nacl local config

    result is base64

    its a combination of nacl symmetric encryption using secret and asymetric encryption using the words

    the result is a super strong encryption

    to use

    """

    #first encrypt symmetric
    secret1 = md5(secret)
    print("secret1:%s"%secret1)
    
    box = nacl.secret.SecretBox(secret1)

    message1 = bytes(message, 'utf-8')

    print("msg:%s"%message1)
    res = box.encrypt(message1)

    #now encrypt asymetric using the words
    privkeybytes = mnemonic.to_entropy(words)
    print("privkey:%s"%privkeybytes)

    pk = PrivateKey(privkeybytes)
    sb = SealedBox(pk.public_key)

    res = sb.encrypt(res)

    res = base64.encodestring(res)

    print("encr:%s"%res)

    #LETS VERIFY

    message_out=res.decode('utf8')
    msg = decrypt(message_out)

    assert msg.strip() == message.strip()         

    return res

def decrypt(message_out):
    """
    """

    secret1 = md5(secret)
    # secret1 = bytes(secret1, 'utf-8')

    # if not j.data.types.bytes.check(message):
    message1 = bytes(message_out,'utf8')
        
    message1 = base64.decodestring(message1)


    privkeybytes = mnemonic.to_entropy(words)

    pk = PrivateKey(privkeybytes)
    sb = SealedBox(pk)

    message_decr = sb.decrypt(message1)

    #now decrypt symmetric
    box = nacl.secret.SecretBox(secret1)
    message_decr =  box.decrypt(message_decr)        
    message_decr = message_decr.decode(encoding='utf-8', errors='strict')

    print("decrypted text:\n*************\n")
    print(message_decr)

    return message_decr


#TEST

encrypt()

def compare_with_js9():
    from js9 import j
    encrypted = encrypt()

    encrypted2 = j.data.nacl.encrypt(secret=secret,message=message,words=words)
    
    msg_back = decrypt(encrypted2.decode('utf8'))

    assert msg_back==message

    print("encryption with js9, is readable by this script")

#not needed to do this when decoding something with only this file
compare_with_js9()