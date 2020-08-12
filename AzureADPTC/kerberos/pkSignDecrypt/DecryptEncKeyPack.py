from windows import winproxy
from AzureADPTC.kerberos.pkSignDecrypt.structs import *
from AzureADPTC.kerberos.pkSignDecrypt.GenFunctions import *

class DUMMYUNIONNAME2(ctypes.Union):
    _fields_ = [("hCryptProv", gdef.HCRYPTPROV),
                ("hNCryptKey", gdef.NCRYPT_KEY_HANDLE)]

class CMSG_CTRL_DECRYPT_PARA(ctypes.Structure):
    _fields_ = [("cbSize", gdef.DWORD),
                ("DUMMYUNIONNAME2", DUMMYUNIONNAME2),
                ("dwKeySpec", gdef.DWORD),
                ("dwRecipientIndex", gdef.DWORD)]

def decrypt_msg(pfxFile, pfxPass, data):
    pfx = file(pfxFile, 'rb').read()
    if isinstance(pfx, (basestring, bytearray)):
        pfx = gdef.CRYPT_DATA_BLOB.from_string(pfx)
    hCertStore = winproxy.PFXImportCertStore(pfx, pfxPass, 0)
    hContext = winproxy.CertFindCertificateInStore(hCertStore, gdef.X509_ASN_ENCODING | gdef.PKCS_7_ASN_ENCODING, 0,
                                                   gdef.CERT_FIND_ANY, None, None)

    bFreeHandle = gdef.c_long()
    dwKeySpec = gdef.DWORD()
    hProv = gdef.HCRYPTPROV()
    winproxy.CryptAcquireCertificatePrivateKey(hContext, gdef.CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, None, hProv,
                                               dwKeySpec, bFreeHandle)

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

    DecryptParam = CMSG_CTRL_DECRYPT_PARA()
    DecryptParam.cbSize = ctypes.sizeof(CMSG_CTRL_DECRYPT_PARA)
    DecryptParam.DUMMYUNIONNAME2.hCryptProv = hProv
    DecryptParam.dwKeySpec = dwKeySpec
    DecryptParam.dwRecipientIndex = 0
    x = ctypes.c_ulong()
    hCryptMsg = winproxy.CryptMsgOpenToDecode(gdef.X509_ASN_ENCODING | gdef.PKCS_7_ASN_ENCODING,
                                              0, 0, None,
                                              None, None)
    ofs = getattr(OCTET, 'length').offset
    pointerDOutputLen = ctypes.pointer(ctypes.c_ulong.from_buffer(output, ofs))
    if hCryptMsg:
        if winproxy.CryptMsgUpdate(hCryptMsg, input.value, input.length, True):
            if winproxy.CryptMsgControl(hCryptMsg, 0, gdef.CMSG_CTRL_DECRYPT, ctypes.pointer(DecryptParam)):
                if winproxy.CryptMsgGetParam(hCryptMsg, gdef.CMSG_CONTENT_PARAM, 0, None, pointerDOutputLen):
                    output.value = ctypes.cast(
                        ctypes.pointer(ctypes.create_string_buffer(pointerDOutputLen.contents.value)),
                        ctypes.POINTER(ctypes.c_ubyte))
                    status = winproxy.CryptMsgGetParam(hCryptMsg, gdef.CMSG_CONTENT_PARAM, 0, None, pointerDOutputLen)
                    if not status:
                        print("CryptMsgGetParam Error")

                    else:
                        output.value = ctypes.cast(
                            ctypes.pointer(ctypes.create_string_buffer(pointerDOutputLen.contents.value)),
                            ctypes.POINTER(ctypes.c_ubyte))
                        if winproxy.CryptMsgGetParam(hCryptMsg, gdef.CMSG_CONTENT_PARAM, 0, output.value,
                                                     pointerDOutputLen):
                            return get_msg(ctypes.pointer(output))
                else:
                    print("CryptMsgGetParam Error")

        else:
            print("CryptMsgUpdate Error")

    else:
        print("CryptMsgOpenToEncode Error")


def get_msg(input):
    x = ctypes.c_ulong()
    hCryptMsg = winproxy.CryptMsgOpenToDecode(gdef.X509_ASN_ENCODING | gdef.PKCS_7_ASN_ENCODING,
                                              0, 0, ctypes.pointer(x),
                                              None, None)
    if hCryptMsg:
        if winproxy.CryptMsgUpdate(hCryptMsg, input.contents.value, input.contents.length, True):
            output = OCTET()
            output.length = gdef.c_uint(0)
            ofs = getattr(OCTET, 'length').offset
            pointerDOutputLen = ctypes.pointer(ctypes.c_ulong.from_buffer(output, ofs))
            if winproxy.CryptMsgGetParam(hCryptMsg, gdef.CMSG_CONTENT_PARAM, 0, None, pointerDOutputLen):
                output.value = ctypes.cast(
                    ctypes.pointer(ctypes.create_string_buffer(pointerDOutputLen.contents.value)),
                    ctypes.POINTER(ctypes.c_ubyte))
                status = winproxy.CryptMsgGetParam(hCryptMsg, gdef.CMSG_CONTENT_PARAM, 0, output.value, pointerDOutputLen)
                if not status:
                    print("CryptMsgGetParam Error")
                else:
                    outData = output._objects['1']['1'].raw
                    data = outData.encode('hex')
                    return data

    return status
