import ctypes
import windows.generated_def as gdef
from windows.generated_def.winstructs import _CRYPTOAPI_BLOB

class DUMMYUNIONNAME(ctypes.Union):
    _fields_ = [("hCryptProv", gdef.HCRYPTPROV),
                ("hNCryptKey", gdef.NCRYPT_KEY_HANDLE)]


class CERT_BLOB(ctypes.Structure):
    _fields_ = [("cbData", gdef.DWORD),
                ("pbData", ctypes.POINTER(gdef.BYTE))]

class CMSG_SIGNER_ENCODE_INFO(ctypes.Structure):
    _fields_ = [("cbSize", gdef.DWORD),
                ("pCertInfo", gdef.PCERT_INFO),
                ("DUMMYUNIONNAME", ctypes.POINTER(gdef.c_ulong)),
                ("dwKeySpec", gdef.DWORD),
                ("HashAlgorithm", gdef.CRYPT_ALGORITHM_IDENTIFIER),
                ("pvHashAuxInfo", ctypes.POINTER(gdef.VOID)),
                ("cAuthAttr", gdef.DWORD),
                ("rgAuthAttr", gdef.PCRYPT_ATTRIBUTE),
                ("cUnauthAttr", gdef.DWORD),
                ("rgUnauthAttr", gdef.PCRYPT_ATTRIBUTE)]


class CMSG_SIGNED_ENCODE_INFO(ctypes.Structure):
    _fields_ = [("cbSize", gdef.DWORD),
                ("cSigners", gdef.DWORD),
                ("rgSigners", ctypes.POINTER(CMSG_SIGNER_ENCODE_INFO)),
                ("cCertEncoded", gdef.DWORD),
                ("rgCertEncoded", ctypes.POINTER(_CRYPTOAPI_BLOB)),
                ("cCrlEncoded", gdef.DWORD),
                ("rgCrlEncoded", gdef.PCRL_BLOB)]

class OCTET(ctypes.Structure):
    _fields_ = [("length", gdef.c_uint),
                ("value", ctypes.POINTER(ctypes.c_ubyte))]


class PROVIDER_INFO:
    def __init__(self, hProv, hKey, dwKeySpec):
        self.hProv = hProv
        self.hKey = hKey
        self.dwKeySpec = dwKeySpec


class CERT_INFO:
    def __init__(self, hCertStore, pCertContext, provider):
        self.hCertStore = hCertStore
        self.pCertContext = pCertContext
        self.provider = provider
