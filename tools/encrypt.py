
import hashlib
from binascii import unhexlify
import nacl
import nacl.secret
import nacl.utils
import base64
from nacl.public import PrivateKey, SealedBox

# from mnemonic import Mnemonic
import binascii
hexlify = binascii.hexlify
# mnemonic = Mnemonic()



def md5(txt):
    txt=txt.encode('utf8')
    m = hashlib.md5()
    m.update(txt)
    md5bin=m.digest()    
    return hexlify(md5bin)

def encrypt(secret=None,message=None):        
    """
    secret is password as used

    result is base64

    its a combination of nacl symmetric encryption using secret and asymetric encryption using the words

    the result is a super strong encryption

    to use

    """

    if not message:
        message = input("give txt you want to encrypt:")
    if not secret:
        secret = input("give secret you want to use:")

    message = message.strip()
    secret = secret.strip()


    #first encrypt symmetric
    secret1 = md5(secret)
    print("secret1:%s"%secret1)

    box = nacl.secret.SecretBox(secret1)

    message1 = bytes(message, 'utf-8')

    print("msg:%s"%message1)
    res = box.encrypt(message1)

    # res = base64.encodestring(res)
    res = hexlify(res)

    print("encr:\n%s"%res)

    #LETS VERIFY

    # message_out=res.decode('utf8')
    msg_checked = decrypt(message=res,secret=secret)

    assert msg_checked.strip() == message.strip()         

    return res

def decrypt(secret=None,message=None):
    """
    """

    if not message:
        message = input("give txt you want to decrypt:")
    if not secret:
        secret = input("give secret you want to use:")

    message = message.strip()

    secret1 = md5(secret)
    # secret1 = bytes(secret1, 'utf-8')

    # if not isinstance(message,bytes):
    #     message = message.encode()

    message=unhexlify(message)
        
    # message1 = base64.decodestring(message)

    box = nacl.secret.SecretBox(secret1)
    message_decr =  box.decrypt(message)        
    message_decr = message_decr.decode(encoding='utf-8', errors='strict')

    print("decrypted text:\n*************\n")
    print(message_decr)

    return message_decr

res=encrypt(message="something",secret="awdf4dfwsf")
assert decrypt(message=res,secret="awdf4dfwsf") == "something"


encrypt()
