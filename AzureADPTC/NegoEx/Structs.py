import ctypes
import random
import string
import uuid
from pyasn1.type import tag, namedtype, univ, constraint, char, useful
from enum import Enum
from pyasn1.codec.der.encoder import encode

class PAC_CREDENTIAL_INFO(ctypes.Structure):
    _fields_ = [("Version", ctypes.c_ulong),
                ("EncryptionType", ctypes.c_ulong),
                ("SerializedData", ctypes.c_char * 1)
                ]

class PAC_INFO_BUFFER(ctypes.Structure):
    _fields_ = [("ulType", ctypes.c_ulong),
                ("cbBufferSize", ctypes.c_ulong),
                ("Offset", ctypes.c_ulonglong)
                ]

class PACTYPE(ctypes.Structure):
    _fields_ = [("cBuffers", ctypes.c_ulong),
                ("Version", ctypes.c_ulong),
                ("Buffers", PAC_INFO_BUFFER * 1)
                ]

class Extensions(ctypes.BigEndianStructure):
    _fields_ = [("data_type", ctypes.c_int), # 4 byte data type
                ("data_length", ctypes.c_int) # 4 byte data length
                ]

def GenerateExtensions(data):
    extensions = Extensions()
    extensions.data_type = 2
    extensions.data_length = len(data.decode('hex'))
    return Pack(extensions) + data

class LSAP_TOKEN_INFO_INTEGRITY(ctypes.Structure):
    _fields_ = [("Flags", ctypes.c_ulong), # 0 for full token and 1 for UAC
                ("TokenIL", ctypes.c_ulong), # 0 for Untrusted, 1000 low, 2000 medium the high, system and protected process
                ("MachineID", ctypes.c_char * 32) # 32 byte binary random string
                ]

def generateRandom(stringLength=32):
    letters = string.ascii_lowercase
    numbers = ''.join(str(i) for i in range(10))
    return ''.join(random.choice(letters + numbers) for i in range(stringLength))

class WST_MESSAGE_TYPE(Enum):
    WST_MESSAGE_TYPE_CLIENT_HELLO = 0
    WST_MESSAGE_TYPE_SERVER_HELLO = 1
    WST_MESSAGE_TYPE_CLIENT_META_DATA = 2
    WST_MESSAGE_TYPE_SERVER_META_DATA = 3
    WST_MESSAGE_TYPE_CHALLENGE = 4
    WST_MESSAGE_TYPE_AP_REQUEST = 5
    WST_MESSAGE_TYPE_VERIFY = 6
    WST_MESSAGE_TYPE_ALERT = 7

class MessageTypes(Enum):
    INITIATOR_NEGO = 0
    ACCEPTOR_NEGO = 1
    INITIATOR_META_DATA = 2
    ACCEPTOR_META_DATA = 3
    CHALLENGE = 4
    AP_REQUEST = 5
    VERIFY = 6

class _WST_AUTH_SCHEME_VECTOR(ctypes.Structure):
    _fields_ = [("AuthSchemeArrayOffset", ctypes.c_ulong),
                ("AuthSchemeCount", ctypes.c_ushort),
                ("AuthSchemePad", ctypes.c_ushort)
                ]

class _WST_EXTENSION_VECTOR(ctypes.Structure):
    _fields_ = [("ExtensionArrayOffset", ctypes.c_ulong),
                ("ExtensionCount", ctypes.c_ushort),
                ("ExtensionPad", ctypes.c_ushort)
                ]

class WST_MESSAGE_SIGNATURE(ctypes.BigEndianStructure):
    _fields_ = [("Signature", ctypes.c_ulonglong)
    ]

class WST_BYTE_VECTOR(ctypes.LittleEndianStructure):
    _fields_ = [("ExchangeOffset", ctypes.c_ulong),
                ("ExchangeByteCount", ctypes.c_ushort),
                ("ExchangePad", ctypes.c_ushort)
                ]

class _WST_CHECKSUM(ctypes.Structure):
    _fields_ = [("cbHeaderLength", ctypes.c_ulong),
                ("ChecksumScheme", ctypes.c_ulong),
                ("ChecksumType", ctypes.c_ulong),
                ("ChecksumValue", WST_BYTE_VECTOR)
                ]

class WST_MESSAGE_HEADER(ctypes.LittleEndianStructure):
    _fields_ = [("Signature", WST_MESSAGE_SIGNATURE),
                ("MessageType", ctypes.c_int),
                ("SequenceNum", ctypes.c_ulong),
                ("cbHeaderLength", ctypes.c_ulong),
                ("cbMessageLength", ctypes.c_ulong),
                ("ConversationId", ctypes.c_ubyte * 16)
                ]

class WST_EXCHANGE_MESSAGE(ctypes.BigEndianStructure):
    _fields_ = [("Header", WST_MESSAGE_HEADER),
                ("AuthScheme", ctypes.c_ubyte * 16),
                ("Exchange", WST_BYTE_VECTOR)
                ]

class _WST_HELLO_MESSAGE(ctypes.BigEndianStructure):
    _fields_ = [("Header", WST_MESSAGE_HEADER),
                ("Random", ctypes.c_ubyte * 32),
                ("ProtocolVersion", ctypes.c_ulonglong),
                ("AuthSchemes", _WST_AUTH_SCHEME_VECTOR),
                ("Extensions", _WST_EXTENSION_VECTOR),
                ("AuthScheme", ctypes.c_ubyte * 16)
                ]

class _WST_VERIFY_MESSAGE(ctypes.BigEndianStructure):
    _fields_ = [("Header", WST_MESSAGE_HEADER),
                ("AuthScheme", ctypes.c_ubyte * 16),
                ("Checksum", _WST_CHECKSUM)
                ]

class PkAuth(ctypes.Structure):
    _fields_ = [("cusec", ctypes.c_int),
                ("time", ctypes.c_ubyte * 16),
                ("nonce", ctypes.c_int),
                ("pachecksum", ctypes.c_ubyte * 0)
                ]

class SMB2_SESSION_SETUP_RESPONSE(ctypes.Structure):
    _fields_ = [("StructureSize", ctypes.c_ubyte * 2),
                ("SessionFlags", ctypes.c_ubyte * 2),
                ("SecurityBufferOffset", ctypes.c_ubyte * 2),
                ("SecurityBufferLength", ctypes.c_ubyte * 2),
                ("Buffer", ctypes.c_ulong)
                ]

def _sequence_component(name, tag_value, type, **subkwargs):
    return namedtype.NamedType(name, type.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple,
                            tag_value),
        **subkwargs))

class ClientInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('clientType', 0, univ.Integer()),
        _sequence_component('clientName', 1, univ.SequenceOf(char.GeneralString())),
    )

class Info(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('pku2u', 0, char.GeneralString()),
        _sequence_component('clientInfo', 1, ClientInfo()),
    )


class CertIssuer(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('1', univ.ObjectIdentifier()),
        namedtype.NamedType('Info', char.BMPString()),
    )

class CertInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('certInfo', 0, univ.Any())
    )

class CertInfos(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certInfos', CertInfo())
    )

def _c(n, t):
    return t.clone(tagSet=t.tagSet + tag.Tag(tag.tagClassContext, tag.tagFormatSimple, n))

class CertIssuers(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certIssuer', _c(0, univ.Any()))
    )

class MetaData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('1', 0, univ.SequenceOf(CertIssuers())),
        _sequence_component('Info', 1, Info()),
    )

def generateMetaDataAsn(remoteComputer, issuer):
    data = MetaData()
    a = univ.SequenceOf(univ.SetOf(CertIssuer()))
    a[0][0]['1'] = '2.5.4.3'
    a[0][0]['Info'] = issuer.encode("utf-16-be")
    data['1'][0]['certIssuer'] = encode(a)
    data['Info']['pku2u'] = "WELLKNOWN:PKU2U"
    data['Info']['clientInfo']['clientType'] = -128
    data['Info']['clientInfo']['clientName'][0] = remoteComputer

    data1 = CertInfos()
    data1['certInfos']['certInfo'] = encode(a)

    return encode(data).encode('hex')


toHex = lambda x: "".join([hex(ord(c))[2:].zfill(2) for c in x])

def Pack(ctype_instance):
    buf = toHex(ctypes.string_at(ctypes.byref(ctype_instance), ctypes.sizeof(ctype_instance)))
    return buf

def Unpack(ctype, buf):
    cstring = ctypes.create_string_buffer(buf)
    ctype_instance = ctypes.cast(ctypes.pointer(cstring), ctypes.POINTER(ctype)).contents
    return ctype_instance

def generateInitiatorNego():
    CONVERSATION_ID = uuid.uuid4().hex

    d = '3bfe3cf76c6d01ea3aff5261bf7d0a4a'
    L = [int(a+b,16) for a,b in zip(d[0::2],d[1::2])] # change from d to CONVERSATION_ID

    guidIn16Bytes = (ctypes.c_ubyte * 16)(*L)


    longnegoex = int(toHex("NEGOEXTS"),16)

    authschem = '5c33530deaf90d4db2ec4ae3786ec308'
    authsc = [int(a + b, 16) for a, b in zip(authschem[0::2], authschem[1::2])]  # change from d to AUTH_SCHEME
    authschemIn16Bytes = (ctypes.c_ubyte * 16)(*authsc)

    ran = 'ffaf0c135369c5075ae3868ec6364dea9615ab5bb22e6c708cf18c133696dd57'
    R = [int(a+b,16) for a,b in zip(ran[0::2],ran[1::2])] # change from d to RANDOM
    randomIn32Bytes = (ctypes.c_ubyte * 32)(*R)

    signature = WST_MESSAGE_SIGNATURE(longnegoex)

    # no need to change
    extenstion = _WST_EXTENSION_VECTOR(0,
                                       0,
                                       0)

    authScheme = _WST_AUTH_SCHEME_VECTOR(96,
                                        1,
                                        0)

    header = WST_MESSAGE_HEADER(signature,
                                0,
                                0, # should start as 0
                                96,
                                112, # should be calculated as all initiator nego
                                guidIn16Bytes
                                )
    print(bytes(header))
    print(Pack(header))

    print(Pack(authScheme))
    initNego = _WST_HELLO_MESSAGE(header,
                                   randomIn32Bytes, # should be generateRandom(),
                                   0,
                                   authScheme,
                                   extenstion,
                                   authschemIn16Bytes)

    #header['cbMessageLength'] = len(initNego)
    print(Pack(initNego))
    return Pack(initNego)

def generateMetaData():
    d = '3bfe3cf76c6d01ea3aff5261bf7d0a4a'
    L = [int(a + b, 16) for a, b in zip(d[0::2], d[1::2])]  # change from d to CONVERSATION_ID

    guidIn16Bytes = (ctypes.c_ubyte * 16)(*L)

    longnegoex = int(toHex("NEGOEXTS"), 16)

    authschem = '5c33530deaf90d4db2ec4ae3786ec308'
    authsc = [int(a + b, 16) for a, b in zip(authschem[0::2], authschem[1::2])]  # change from d to AUTH_SCHEME
    authschemIn16Bytes = (ctypes.c_ubyte * 16)(*authsc)

    signature = WST_MESSAGE_SIGNATURE(longnegoex)

    header2 = WST_MESSAGE_HEADER(signature,
                                2,
                                3, # change to 1
                                0,# change to ctypes.sizeof(header) + 8,
                                207,# should be 112,  # should be calculated as all initiator nego
                                guidIn16Bytes
                                )

    exchange2 = WST_BYTE_VECTOR(64, # should be ctypes.sizeof(header) + 8,
                               int(len(data) / 2),
                               0)

    exchangeMsg2 = WST_EXCHANGE_MESSAGE(header2,
                                       authschemIn16Bytes,
                                       exchange2)

    header = WST_MESSAGE_HEADER(signature,
                                 2,
                                 1,  # change to 1
                                 ctypes.sizeof(header2) + 24,
                                 ctypes.sizeof(exchangeMsg2) + int(len(data) / 2),
                                 guidIn16Bytes
                                 )

    exchange = WST_BYTE_VECTOR(ctypes.sizeof(header) + 24,
                                int(len(data) / 2),
                                0)

    exchangeMsg = WST_EXCHANGE_MESSAGE(header,
                                        authschemIn16Bytes,
                                        exchange)


    print(Pack(exchangeMsg))
    return Pack(exchangeMsg) + data

def generateApRequest(): # same struct as meta data
    d = '3bfe3cf76c6d01ea3aff5261bf7d0a4a'
    L = [int(a + b, 16) for a, b in zip(d[0::2], d[1::2])]  # change from d to CONVERSATION_ID

    guidIn16Bytes = (ctypes.c_ubyte * 16)(*L)

    longnegoex = int(toHex("NEGOEXTS"), 16)

    authschem = '5c33530deaf90d4db2ec4ae3786ec308'
    authsc = [int(a + b, 16) for a, b in zip(authschem[0::2], authschem[1::2])]  # change from d to AUTH_SCHEME
    authschemIn16Bytes = (ctypes.c_ubyte * 16)(*authsc)

    signature = WST_MESSAGE_SIGNATURE(longnegoex)

    header2 = WST_MESSAGE_HEADER(signature,
                                 5,
                                 4,  # change to 2
                                 0,
                                 0,
                                 guidIn16Bytes
                                 )

    exchange2 = WST_BYTE_VECTOR(64,  # should be ctypes.sizeof(header) + 8,
                                int(len(data) / 2),
                                0)

    exchangeMsg2 = WST_EXCHANGE_MESSAGE(header2,
                                        authschemIn16Bytes,
                                        exchange2)

    header = WST_MESSAGE_HEADER(signature,
                                5,
                                2,
                                ctypes.sizeof(header2) + 24,
                                ctypes.sizeof(exchangeMsg2) + int(len(data) / 2),
                                guidIn16Bytes
                                )

    exchange = WST_BYTE_VECTOR(ctypes.sizeof(header) + 24,
                               int(len(data) / 2),
                               0)

    ApRequestMsg = WST_EXCHANGE_MESSAGE(header,
                                       authschemIn16Bytes,
                                       exchange)

    return Pack(ApRequestMsg) + data
    print(Pack(ApRequestMsg))

def splitStructs(data, nego):
    # each struct statswith NEGOEXTS
    structs = data.split(str(toHex("NEGOEXTS")))
    returnStructs = [str(toHex("NEGOEXTS")) + i for i in structs if i != '']
    # raise sequence number for every struct got
    for struct in structs:
        if struct == '':
            continue
        nego.raiseSequenceNum() 
    for struct in structs:
        if struct == '':
            continue
        if struct.startswith("{0:0{1}x}".format(MessageTypes.CHALLENGE.value,2)):
            structData = str(toHex("NEGOEXTS")) + struct
            
            exchange = Unpack(WST_EXCHANGE_MESSAGE, structData)._fields_[2][1]
            # exchange starts from header + authscheme (40 + 16)
            # then we calculate ExchangeByteCount, ExchangeOffset, ExchangePad
            # and then AS response starts
            return structData[(40 + 16 + exchange.ExchangeByteCount.size + exchange.ExchangeOffset.size + exchange.ExchangePad.size) * 2:], returnStructs

def toLitEndian(hexStream):
    lis = [ hexStream[i:i+2] for i in range(0, len(hexStream), 2) ]
    lis.reverse()
    return ''.join(lis) 
