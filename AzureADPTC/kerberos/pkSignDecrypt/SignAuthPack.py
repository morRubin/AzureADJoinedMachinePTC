from windows import winproxy
from AzureADPTC.kerberos.pkSignDecrypt.structs import *
from AzureADPTC.kerberos.pkSignDecrypt.GenFunctions import *

def sign_msg(pfxFile, pfxPass, data):
    pfx = file(pfxFile, 'rb').read()
    if isinstance(pfx, (basestring, bytearray)):
        pfx = gdef.CRYPT_DATA_BLOB.from_string(pfx)
    hCertStore = winproxy.PFXImportCertStore(pfx, pfxPass, 0)
    hContext = winproxy.CertFindCertificateInStore(hCertStore, gdef.X509_ASN_ENCODING | gdef.PKCS_7_ASN_ENCODING, 0,
                                                   gdef.CERT_FIND_ANY, None, None)

    bFreeHandle = gdef.c_long()
    dwKeySpec = gdef.DWORD()
    hProv = gdef.HCRYPTPROV()
    try:
        winproxy.CryptAcquireCertificatePrivateKey(hContext, gdef.CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, None, hProv, dwKeySpec, bFreeHandle)
    except Exception as e:
        if str(e).startswith('CryptAcquireCertificatePrivateKey: [Error 2148081675]'):
            raise Exception("Couldn't Acquire Certificate Private Key")
    
    hCertPubKey = gdef.HCRYPTKEY()
    handleKey = gdef.PVOID()
    pInfo = ctypes.pointer(hContext.contents.pCertInfo.contents.SubjectPublicKeyInfo)
    CryptImportPublicKeyInfoEx2(gdef.X509_ASN_ENCODING | gdef.PKCS_7_ASN_ENCODING, pInfo, 0, None, ctypes.pointer(handleKey))

    provInfo = PROVIDER_INFO(hProv, handleKey, dwKeySpec)

    hexstream = bytearray.fromhex(data)
    rawData = (ctypes.c_ubyte * len(hexstream)).from_buffer_copy(hexstream)
    input = OCTET(ctypes.sizeof(rawData), rawData)
    output = OCTET()
    output.length = gdef.c_uint(0)

    Signers = CMSG_SIGNER_ENCODE_INFO()
    Signers.cbSize = ctypes.sizeof(CMSG_SIGNER_ENCODE_INFO)
    Signers.pCertInfo = hContext.contents.pCertInfo
    Signers.DUMMYUNIONNAME = provInfo.hProv
    Signers.dwKeySpec = provInfo.dwKeySpec

    Signers.HashAlgorithm = gdef.CRYPT_ALGORITHM_IDENTIFIER(gdef.szOID_OIWSEC_sha1, gdef.CRYPT_OBJID_BLOB(0, None))
    Signers.pvHashAuxInfo = None #ctypes.cast(0, ctypes.POINTER(ctypes.c_ulong))
    Signers.cAuthAttr = 0
    Signers.rgAuthAttr = None
    Signers.cUnauthAttr = 0
    Signers.rgUnauthAttr = None

    Certificate = CERT_BLOB()
    Certificate.cbData = hContext.contents.cbCertEncoded
    Certificate.pbData = hContext.contents.pbCertEncoded

    MsgEncodeInfo = CMSG_SIGNED_ENCODE_INFO()
    MsgEncodeInfo.cbSize = ctypes.sizeof(CMSG_SIGNED_ENCODE_INFO)
    MsgEncodeInfo.cSigners = 1
    MsgEncodeInfo.rgSigners = ctypes.pointer(Signers)
    MsgEncodeInfo.cCertEncoded = 1
    MsgEncodeInfo.rgCertEncoded = ctypes.pointer(Certificate)
    MsgEncodeInfo.cCrlEncoded = 0
    MsgEncodeInfo.rgCrlEncoded = None

    try:
        hCryptMsg = winproxy.CryptMsgOpenToEncode(gdef.X509_ASN_ENCODING | gdef.PKCS_7_ASN_ENCODING,
                                                  gdef.CMSG_CMS_ENCAPSULATED_CONTENT_FLAG, gdef.CMSG_SIGNED,
                                                  ctypes.pointer(MsgEncodeInfo), "1.3.6.1.5.2.3.1", None)
    except Exception as e:
        if str(e).startswith('CryptMsgOpenToEncode: [Error 2147942487]'):
            raise Exception("Couldn't Message Open To Encode, Invalid PIN Provided")
        
    ofs = getattr(OCTET, 'length').offset
    pointerDOutputLen = ctypes.pointer(ctypes.c_ulong.from_buffer(output,ofs))
    if hCryptMsg:
        if winproxy.CryptMsgUpdate(hCryptMsg, input.value, input.length, True):
            if winproxy.CryptMsgGetParam(hCryptMsg, gdef.CMSG_CONTENT_PARAM, 0, None, pointerDOutputLen):
                output.value = ctypes.cast(ctypes.pointer(ctypes.create_string_buffer(pointerDOutputLen.contents.value)), ctypes.POINTER(ctypes.c_ubyte))
                status = winproxy.CryptMsgGetParam(hCryptMsg, gdef.CMSG_CONTENT_PARAM, 0, output.value, pointerDOutputLen)
                if not status:
                    print("CryptMsgGetParam Error")

                else:
                    outData = output._objects['1']['1']
                    return outData.raw.encode('hex')

            else:
                print("CryptMsgGetParam Error")

        else:
            print("CryptMsgUpdate Error")

    else:
        print("CryptMsgOpenToEncode Error")
