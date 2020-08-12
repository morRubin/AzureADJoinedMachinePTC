import sys
from socket import socket
from random import getrandbits
from time import time, localtime, strftime
import hashlib

from pyasn1.type.univ import Integer, Sequence, SequenceOf, OctetString, BitString, Boolean
from pyasn1.type.char import GeneralString
from pyasn1.type.useful import GeneralizedTime
from pyasn1.type.tag import Tag, tagClassContext, tagClassApplication, tagFormatSimple
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode
from pyasn1.type import univ

from struct import pack, unpack

from impacket.krb5.crypto import Key, _enctype_table, InvalidChecksum
from impacket.krb5 import types
from impacket.krb5.crypto import Enctype

import OpenSSL

from AzureADPTC.kerberos.PkinitAsn import *

import binascii
import struct

import six
import hashlib
import datetime

from AzureADPTC.kerberos.pkSignDecrypt.SignAuthPack import *

from cryptography.hazmat.backends.interfaces import DHBackend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

def _c(n, t):
    return t.clone(tagSet=t.tagSet + Tag(tagClassContext, tagFormatSimple, n))

NT_UNKNOWN = 0
NT_PRINCIPAL = 1
NT_SRV_INST = 2
NT_SRV_HST = 3
NT_SRV_XHST = 4
NT_UID = 5
NT_X500_PRINCIPAL = 6
NT_SMTP_NAME = 7
NT_ENTERPRISE = 10


AD_IF_RELEVANT = 1
AD_WIN2K_PAC = 128

def _v(n, t):
    return t.clone(tagSet=t.tagSet + Tag(tagClassContext, tagFormatSimple, n), cloneValueFlag=True)

def BuildPkinit_pa(user_cert, cert_pass, reqbodyHex, diffieHellmanExchange):
    paAsReq = PA_PK_AS_REQ()

    timestamp = (datetime.datetime.utcnow().isoformat()[:-7] + 'Z').replace('-','').replace(':','').replace('T','')
    authpack = AuthPack()

    checksum = hashlib.sha1(reqbodyHex).hexdigest()
    
    authpack['pkAuthenticator']['cusec'] = 275425
    authpack['pkAuthenticator']['ctime'] = timestamp
    authpack['pkAuthenticator']['nonce'] = 0
    authpack['pkAuthenticator']['paChecksum'] = bytearray.fromhex(checksum) #reqBodyChecksum

    aidentifier2 = AlgorithmIdentifier()

    seq = univ.Sequence(componentType=namedtype.NamedTypes(
        namedtype.NamedType('1', univ.Integer()),
        namedtype.NamedType('2', univ.Integer())
    ))  # public key for DH y = g^x mod p
    
    # longPrime- n or p
    seq['1'] = int('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16)  # safe prime

    # generator- g
    seq['2'] = 2

    aidentifier2['algorithm'] = '1.2.840.10046.2.1'
    aidentifier2['parameters'] = seq

    # client public key as g^privateKey mod n
    subjectPublicKey = '0e64a81b095929c181cf8037ef49d5b12ac1e1b192b58b3309c1165d5a42f1e588973bc41a47381c1347f72e9573c1458bb1e818a1b03036860ac539e081461eaab3c80c6099ea8c1552f0b146f125f300da3e776b3b298d31b5a564a26918bbe1d1f3a9aafea80f2b6bb20327aeb6e4c61ab6d55d412d2e2290f73b10937b69'
    sub = '80000000000000000000000000000000000'
    subjectPublicKeyHex = '038184000281800e64a81b095929c181cf8037ef49d5b12ac1e1b192b58b3309c1165d5a42f1e588973bc41a47381c1347f72e9573c1458bb1e818a1b03036860ac539e081461eaab3c80c6099ea8c1552f0b146f125f300da3e776b3b298d31b5a564a26918bbe1d1f3a9aafea80f2b6bb20327aeb6e4c61ab6d55d412d2e2290f73b10937b69'

    # added BitString - 03 and then sizes 81, 85 and encapsulation 00 to Integer
    encodedPublic = encode(univ.Integer(diffieHellmanExchange[1].public_key().public_numbers().y)).encode('hex')
    sizeWithoutTags = str(hex(len(hex(diffieHellmanExchange[1].public_key().public_numbers().y)[2:-1]) / 2 + 1)[2:])
    sizeWithTags = str(hex(len(encodedPublic) / 2 + 1)[2:])

                           #sizeWithoutTags
    encodedPublic = '03' + '81' + sizeWithTags + '00' + encodedPublic
    
    authpack['clientPublicValue']['algorithm'] = aidentifier2
    authpack['clientPublicValue']['subjectPublicKey'] = bytearray.fromhex(encodedPublic)

    dhNonce = '6B328FA66EEBDFD3D69ED34E5007776AB30832A2ED1DCB1699781BFE0BEDF87A'
    authpack['clientDHNonce'] = bytearray.fromhex(dhNonce)
    
    authPackData = encode(authpack).encode('hex')

    return sign_msg(user_cert, cert_pass, authPackData)

def build_req_body_NegoEx(remoteComputer, cname, req):   
    req_body = KdcReqBody()

    # (Forwardable, Proxiable, Renewable, Canonicalize)
    req_body['kdc-options'] = "'01000000100000010000000000010000'B"
    req_body['cname']['name-type'] = -128
    req_body['cname']['name-string'][0] = cname
    req_body['realm'] = "WELLKNOWN:PKU2U"
    
    req_body['sname']['name-type'] = -128
    req_body['sname']['name-string'][0] = remoteComputer

    req_body['till'] = '20370913024805Z'
    req_body['rtime'] = '20370913024805Z'
    req_body['nonce'] = 0 #nonce
    
    req_body['etype'][0] = 18
    req_body['etype'][1] = 17
    req_body['etype'][2] = 23
    req_body['etype'][3] = 24
    req_body['etype'][4] = -135
    
    req_body['addresses'][0]['addr-type'] = 20
    req_body['addresses'][0]['address'] = 'notMimikatz'

    req['Kerberos']['AsReq']['req-body']['kdc-options'] = "'01000000100000010000000000010000'B"
    req['Kerberos']['AsReq']['req-body']['cname']['name-type'] = -128
    req['Kerberos']['AsReq']['req-body']['cname']['name-string'][0] = cname
    req['Kerberos']['AsReq']['req-body']['realm'] = "WELLKNOWN:PKU2U"
    
    req['Kerberos']['AsReq']['req-body']['sname']['name-type'] = -128
    req['Kerberos']['AsReq']['req-body']['sname']['name-string'][0] = remoteComputer

    req['Kerberos']['AsReq']['req-body']['till'] = '20370913024805Z'
    req['Kerberos']['AsReq']['req-body']['rtime'] = '20370913024805Z'
    req['Kerberos']['AsReq']['req-body']['nonce'] = 0 #nonce
    
    req['Kerberos']['AsReq']['req-body']['etype'][0] = 18
    req['Kerberos']['AsReq']['req-body']['etype'][1] = 17
    req['Kerberos']['AsReq']['req-body']['etype'][2] = 23
    req['Kerberos']['AsReq']['req-body']['etype'][3] = 24
    req['Kerberos']['AsReq']['req-body']['etype'][4] = -135
    
    req['Kerberos']['AsReq']['req-body']['addresses'][0]['addr-type'] = 20
    req['Kerberos']['AsReq']['req-body']['addresses'][0]['address'] = 'notMimikatz'

    return req_body

def build_as_req_negoEx(user_cert, cert_pass, remoteComputer, diffieHellmanExchange):

    pfx = open(user_cert, 'rb').read()
    p12 = OpenSSL.crypto.load_pkcs12(pfx, cert_pass)
    cert = p12.get_certificate()

    for i in cert.get_subject().get_components():
        if i[1].startswith("S-1-12"):
            userSID = i[1]
        elif len(i[1].split("@")):
            userName = i[1]
    userSID = cert.get_subject().CN.encode('utf-8')
    issuer = cert.get_issuer().CN.encode('utf-8')

    cname = "AzureAD\\" + issuer + "\\" + userSID

    as_req = AsReq()
    req = SPNEGO_PKINIT()
    req_body = build_req_body_NegoEx(remoteComputer, cname, req)
    
    padata = BuildPkinit_pa(user_cert, cert_pass, encode(req_body), diffieHellmanExchange)
    
    newPaData = NegoPAData()
    newPaData['value'] = bytearray.fromhex(padata[38:])
    newPaData = encode(newPaData).encode('hex')

    ########################################################################
    # there is a problem with asn1 encapsulation so i had to manually insert 
    pack = newPaData[16:]
    packNewData = newPaData[:8] + '8082' + "{0:0{1}x}".format((len(pack) / 2),4) + pack

    as_req['pvno'] = 5
    as_req['msg-type'] = 10

    as_req['padata'][0]['padata-type'] = 16
    as_req['padata'][0]['padata-value'] = bytearray.fromhex(packNewData) #bytearray.fromhex(padata)
    as_req['req-body'] = _c(4, req_body)

    req['kerberos-v5'] = ' 1.3.6.1.5.2.7'
    req['null'] = univ.Null()
    req['Kerberos']['AsReq']['pvno'] = 5
    req['Kerberos']['AsReq']['msg-type'] = 10
    req['Kerberos']['AsReq']['padata'][0]['padata-type'] = 16
    req['Kerberos']['AsReq']['padata'][0]['padata-value'] = bytearray.fromhex(packNewData) #bytearray.fromhex(encode(newPaData).encode('hex'))
    
    return issuer, encode(req).encode('hex')

def send_req(req, kdc, port=88):
    data = encode(req)
    data = pack('>I', len(data)) + data
    sock = socket()
    sock.connect((kdc, port))
    sock.send(data)
    return sock

def recv_rep(sock):
    data = ''
    datalen = None
    while True:
        rep = sock.recv(8192)
        if not rep:
            sock.close()
            raise IOError('Connection error')
        data += rep
        if len(rep) >= 4:
            if datalen is None:
                datalen = unpack('>I', rep[:4])[0]
            if len(data) >= 4 + datalen:
                sock.close()
                return data[4:4 + datalen]

def truncate(value, keysize):
    SHA_DIGEST_LENGTH = 20
    value = bytearray.fromhex(value)
    output = ''
    currentNum = 0
    while len(output) < keysize:
        currentHexNum = "{0:0{1}x}".format(currentNum,2)
        m = hashlib.sha1()
        m.update(bytearray.fromhex(currentHexNum) + value)
        currentDigest = m.digest()
        if len(output) + len(currentDigest) > keysize:
            output += currentDigest[:keysize - len(output)]
            break
        output += currentDigest
        currentNum += 1  
   
    return output

def decrypt_pk_dh(data, user_cert, cert_pass, diffieHellmanExchange):
    try:
        rep = decode(data, asn1Spec=SPNEGO_PKINIT_REP())[0]['Kerberos']
    except:
        err = decode(data, asn1Spec=KRB_ERROR())[0]
        raise Exception('Kerberos Error ' + ErrorCodes(err['error-code']).name)

    # remove Octet String manualy
    padata = str(rep['padata'][0]['padata-value']).encode('hex')
    parsedPadata = decode(padata.decode('hex'), asn1Spec=AS_REP_Padata())[0]
    decoded = parsedPadata['DHRepInfo']['dhSignedData']
    kdcSignedDataResponse = decode(decoded, asn1Spec=SignedData())[0]
    kdcDHKeyInfo = str(kdcSignedDataResponse['encapContentInfo']['id-pkinit-authData-value']).encode('hex')
    d = decode(kdcDHKeyInfo.decode('hex'), asn1Spec=KDCDHKeyInfo())[0]
    dcPublicKey = int(encode(d['subjectPublicKey']).encode('hex')[20:],16)

    dcPublicNumbers = dh.DHPublicNumbers(dcPublicKey, diffieHellmanExchange[2])

    backend = default_backend()
    
    dcPublicKey = backend.load_dh_public_numbers(dcPublicNumbers)
    shared_key = diffieHellmanExchange[1].exchange(dcPublicKey)
    sharedHexKey = shared_key.encode('hex')

    clientDHNonce = '6B328FA66EEBDFD3D69ED34E5007776AB30832A2ED1DCB1699781BFE0BEDF87A'
    serverDHNonce = encode(parsedPadata['DHRepInfo']['encKeyPack']).encode('hex')[8:]

    fullKey = sharedHexKey + clientDHNonce + serverDHNonce

    etype = rep['enc-part']['etype']
    cipher = _enctype_table[etype]
    if etype == Enctype.AES256:
        truncateKey = truncate(fullKey, 32)
        key = Key(cipher.enctype, truncateKey)

    elif etype == Enctype.AES128:
        truncateKey = truncate(fullKey, 16)
        key = Key(cipher.enctype, truncateKey)

    elif etype == Enctype.RC4:
        truncateKey = truncate(fullKey, 16)
        key = Key(cipher.enctype, truncateKey)

    cipherText = rep['enc-part']['cipher'].asOctets()
    plainText = cipher.decrypt(key, 3, cipherText)
    encASRepPart = decode(plainText, asn1Spec = EncASRepPart())[0]
    cipher = _enctype_table[ int(encASRepPart['key']['keytype'])]
    session_key = Key(cipher.enctype, encASRepPart['key']['keyvalue'].asOctets())
    return session_key, cipher, rep
