from AzureADPTC.NegoEx.Structs import _WST_EXTENSION_VECTOR, WST_MESSAGE_SIGNATURE, _WST_AUTH_SCHEME_VECTOR, WST_MESSAGE_HEADER, _WST_HELLO_MESSAGE,\
    WST_EXCHANGE_MESSAGE, WST_BYTE_VECTOR, WST_MESSAGE_TYPE, _WST_CHECKSUM, _WST_VERIFY_MESSAGE, Pack
import string, random, ctypes
from impacket.uuid import generate

from impacket.krb5.crypto import _checksum_table, Enctype
from impacket.krb5.crypto import Key, _enctype_table, InvalidChecksum
from impacket.krb5.constants import KERB_NON_KERB_CKSUM_SALT, ChecksumTypes

def generateRandom(stringLength=32):
    letters = string.ascii_lowercase
    numbers = ''.join(str(i) for i in range(10))
    return ''.join(random.choice(letters + numbers) for i in range(stringLength))

toHex = lambda x: "".join([hex(ord(c))[2:].zfill(2) for c in x])

class Negoex:
    def __init__(self):
        self.conversation_id = generate().encode('hex')
        self.authscheme = '5c33530deaf90d4db2ec4ae3786ec308'
        self.random = generateRandom().encode('utf-8').encode('hex')
        self.negoexHeader = int(toHex("NEGOEXTS"),16)
        PconvId = [int(a+b,16) for a,b in zip(self.conversation_id[0::2],self.conversation_id[1::2])]
        PauthScheme = [int(a + b, 16) for a, b in zip(self.authscheme[0::2], self.authscheme[1::2])]
        Prandom = [int(a + b, 16) for a, b in zip(self.random[0::2], self.random[1::2])]
        self.convId16Byte = (ctypes.c_ubyte * 16)(*PconvId)
        self.authScheme16Byte = (ctypes.c_ubyte * 16)(*PauthScheme)
        self.random32Byte = (ctypes.c_ubyte * 32)(*Prandom)
        self.sequenceNum = 0

    def generateInitiatorNego(self):
        signature = WST_MESSAGE_SIGNATURE(self.negoexHeader)

        # no need to change
        extention = _WST_EXTENSION_VECTOR(0,
                                           0,
                                           0)

        authscheme = _WST_AUTH_SCHEME_VECTOR(96,
                                             1,
                                             0)

        header = WST_MESSAGE_HEADER(signature,
                                    WST_MESSAGE_TYPE.WST_MESSAGE_TYPE_CLIENT_HELLO.value,
                                    self.sequenceNum,  # should start as 0
                                    96,
                                    112,  # should be calculated as all initiator nego
                                    self.convId16Byte
                                    )

        initnego = _WST_HELLO_MESSAGE(header,
                                      self.random32Byte,  # should be generateRandom(),
                                      0,
                                      authscheme,
                                      extention,
                                      self.authScheme16Byte)

        self.sequenceNum += 1
        return Pack(initnego)

    def generateMetaData(self, data):
        signature = WST_MESSAGE_SIGNATURE(self.negoexHeader)

        header2 = WST_MESSAGE_HEADER(signature,
                                     2,
                                     self.sequenceNum,
                                     0,  # change to ctypes.sizeof(header) + 8,
                                     207,  # should be 112,  # should be calculated as all initiator nego
                                     self.convId16Byte
                                     )
        
        exchange2 = WST_BYTE_VECTOR(64,  # should be ctypes.sizeof(header) + 8,
                                    int(len(data) / 2),
                                    0)

        exchangeMsg2 = WST_EXCHANGE_MESSAGE(header2,
                                            self.authScheme16Byte,
                                            exchange2)

        header = WST_MESSAGE_HEADER(signature,
                                    WST_MESSAGE_TYPE.WST_MESSAGE_TYPE_CLIENT_META_DATA.value,
                                    self.sequenceNum,
                                    ctypes.sizeof(header2) + 24,
                                    ctypes.sizeof(exchangeMsg2) + int(len(data) / 2),
                                    self.convId16Byte
                                    )

        exchange = WST_BYTE_VECTOR(ctypes.sizeof(header) + 24,
                                   int(len(data) / 2),
                                   0)

        exchangeMsg = WST_EXCHANGE_MESSAGE(header,
                                           self.authScheme16Byte,
                                           exchange)

        self.sequenceNum += 1
        return Pack(exchangeMsg) + data

    def generateAPRequest(self,data=None):  # same struct as meta data
        signature = WST_MESSAGE_SIGNATURE(self.negoexHeader)

        header2 = WST_MESSAGE_HEADER(signature,
                                     5,
                                     self.sequenceNum,
                                     0,
                                     0,
                                     self.convId16Byte
                                     )
        #data = '608209d606062b060105020705006a8209c8308209c4a103020105a20302010aa38208a9308208a5308208a1a103020110a282089804820894308208908082088c30820888020103310b300906052b0e03021a05003082021e06072b060105020301a08202110482020d30820209a0393037a0050203020084a111180f32303139303832383131323734375aa203020100a31604142a52bdbff672520519a96ec3f75eab6f5823f9dea18201a6308201a23082011706072a8648ce3e02013082010a02818100ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff0201020281807fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f67329c0ffffffffffffffff038184000281803766d75d758d7a39c591ca6dd198f939ead13b0c380a339a00bb7843b39a1ec1b48967bfe4260b8681dbb3825d25e7d4e0ae725c11f337120f1fb04e16ee05d85ad014971db41e318f75490b3c1810d01e883c0d3568e605f32295ab797220a4cc0becba2301b386993d728f61f8cd2025f75dcf4702cba0546bad69279182b0a322042077894267f42d845750b220d0c1b25569f0a4c85a5f2157658039665c3ddc6bfca0820487308204833082036ba0030201020210503348893797232877b8a0265be6f07b300d06092a864886f70d01010b0500304d314b304906035504031e42004d0053002d004f007200670061006e0069007a006100740069006f006e002d005000320050002d0041006300630065007300730020005b0032003000310039005d301e170d3139303832383131323234375a170d3139303832383132323734375a3081a131343032060a0992268993f22c640119162430313562643736332d323339352d343861312d383963362d373861306465623765343338313d303b06035504030c34532d312d31322d312d313738393433353539352d313330313432313936372d333730323532353331332d32313838313139303131312a302806035504030c2172686f6c744061747072657365617263682e6f6e6d6963726f736f66742e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100ba591b9e998f581874f43646613d9e4c2dcfeaf77468e747062f7bba806f6c3bee794c1087b5a7be6b6a1c64659dccd0b35472a6a729d07688b984fe2cef7380fd5f8255b52192d8f157f52438556a2ea27325234ce8cfad9b2a2a8d8a2321d9784293783b860e768bb39d176f6e82ab456c13e8666826c800723c9193421097ddf7d1520b03c9be233f23175e6500aaca00d5e62710a395879320343c4a59d4ab64f591b118ca9a6ffe0be54fbdf03e847c3ece9dd923b6d159b20c21e945c1c1fdeaecafc66bf0da5031a4c48cc5d7f2700e0bcbaad60add1a9c0b33ee537f4957653a4bed160f62793af6cc9615a31a3211e08b90fa163134a008b2b91d250203010001a382010830820104300e0603551d0f0101ff0404030205a0303c0603551d1104353033a031060a2b060104018237140203a0230c2172686f6c744061747072657365617263682e6f6e6d6963726f736f66742e636f6d30130603551d25040c300a06082b06010505070302301b06092b060104018237150a040e300c300a06082b060105050703023081810603551d11047a3078a07606092b0601040182375a01a0690467532d312d31322d312d3934343833393437352d313131363933333938352d313436373932383530392d323036303931343836362c532d312d31322d312d333236353236353038342d313230343937393735392d333030383133373134352d363039373634363835300d06092a864886f70d01010b050003820101002d87fae5984f28566d2819e41d0c4f856c094b4e3bef2b5641acd0a01107173a6502890cce3af1831ecf38819b621e21b2b25294b2181df4b92720cd46f2afb581b683201746eb24f629d00ea18d7ac15b53115350248a6794d9b32f462e5d91580ffc50b6d0e83b40dc319611e15cbb8a3887e73ed34fbffbcfcd46c6cd7fe71e725c7ce5639e02f16532c8f7034647c10ed1086b7d7ef1bb8c59da6341b435ed871653d409e74544828800a4f97a5535691ba12df600192fd59471c42057c53eae3720cf4605e852f99c3d0493bc3c1aed4214c90d9c218f1afd22c3980ec3d6cc34a5e3ef31fe726fc6e8865a38bd47feb38f09f919fa29e95d281dd37150318201c7308201c30201013061304d314b304906035504031e42004d0053002d004f007200670061006e0069007a006100740069006f006e002d005000320050002d0041006300630065007300730020005b0032003000310039005d0210503348893797232877b8a0265be6f07b300906052b0e03021a0500a03d301606092a864886f70d010903310906072b060105020301302306092a864886f70d0109043116041452eb3e3a092f26dd56c31a9fca3afffd1d1a455b300d06092a864886f70d010101050004820100a20f54a9ddda3cdfd3a04f5ffb7572888040975eec2e04b5fd4323b3a1b7968364082cc1575a2c92e149660a7d6e0cb7a78323c910edefbf0dbd6dc1a581a06464aa4ad16a6e09a9c6f7ac1ac4a068440f07787feb1ad87c4dd2927e3e3e58d34fabe9f7ef5cab21e5ed4bd22730376b6b4f55d142f6c654bba1c38842c3698ce8abb51e7019d295e58219886aab482fd93d7b809fa18dda2a388c212b711d412055ae5b1c922f90f8f9e7e0c1ae3399252aa72de5b475c04d8ee770a91d2983fc3c8366b69b10611a0430314611d7101fb6404439f87b5ed86748cdeeea2d04f8f5cd9db84c03bcb9c4bfb10fc7493aed9ac33bec3116bf9fdcb16c8f026a51a482010930820105a00703050040810010a16b3069a003020180a16230601b5e417a75726541445c4d532d4f7267616e697a6174696f6e2d5032502d416363657373205b323031395d5c532d312d31322d312d313738393433353539352d313330313432313936372d333730323532353331332d32313838313139303131a2111b0f57454c4c4b4e4f574e3a504b553255a31c301aa003020180a11330111b0f4445534b544f502d4e304b54345345a511180f32303337303931343032343830355aa611180f32303337303931343032343830355aa703020100a81230100201120201110201170201180202ff79a91d301b3019a003020114a11204104445534b544f502d50344e564d493320'

        exchange2 = WST_BYTE_VECTOR(64,  # should be ctypes.sizeof(header) + 8,
                                    int(len(data) / 2),
                                    0)

        exchangeMsg2 = WST_EXCHANGE_MESSAGE(header2,
                                            self.authScheme16Byte,
                                            exchange2)

        header = WST_MESSAGE_HEADER(signature,
                                    WST_MESSAGE_TYPE.WST_MESSAGE_TYPE_AP_REQUEST.value,
                                    self.sequenceNum,
                                    ctypes.sizeof(header2) + 24,
                                    ctypes.sizeof(exchangeMsg2) + int(len(data) / 2),
                                    self.convId16Byte
                                    )

        exchange = WST_BYTE_VECTOR(ctypes.sizeof(header) + 24,
                                   int(len(data) / 2),
                                   0)

        ApRequestMsg = WST_EXCHANGE_MESSAGE(header,
                                            self.authScheme16Byte,
                                            exchange)
        self.sequenceNum += 1
        return Pack(ApRequestMsg) + data

    def generateVerify(self, checksumToSend='000000000000000000000001'): # check if correct
        signature = WST_MESSAGE_SIGNATURE(self.negoexHeader)

        header2 = WST_MESSAGE_HEADER(signature,
                                     WST_MESSAGE_TYPE.WST_MESSAGE_TYPE_VERIFY.value,
                                     self.sequenceNum,
                                     0,
                                     0,
                                     self.convId16Byte
                                     )

        checksumvector2 = WST_BYTE_VECTOR(0,
                                          len(checksumToSend) / 2,
                                          0)

        checksum2 = _WST_CHECKSUM(0,
                                  1,
                                  16,
                                  checksumvector2)

        verify2 = _WST_VERIFY_MESSAGE(header2,
                                      self.authScheme16Byte,
                                      checksum2)

        header = WST_MESSAGE_HEADER(signature,
                                     WST_MESSAGE_TYPE.WST_MESSAGE_TYPE_VERIFY.value,
                                     self.sequenceNum,
                                     # changed to 80 as the first header and second
                                     80,#ctypes.sizeof(header2) + 24,
                                     ctypes.sizeof(verify2) + len(checksumToSend) / 2,
                                     self.convId16Byte
                                     )

        checksumvector = WST_BYTE_VECTOR(ctypes.sizeof(verify2),
                                          len(checksumToSend) / 2,
                                          0)

        checksum = _WST_CHECKSUM(ctypes.sizeof(checksum2),
                                  1,
                                  16,
                                  checksumvector)

        verify = _WST_VERIFY_MESSAGE(header,
                                      self.authScheme16Byte,
                                      checksum)

        self.sequenceNum += 1
        return Pack(verify) + checksumToSend

    def negoexAsRequest(self, metaData, data):
        # create data from kerberos as request and send to generateAPRequest
        return self.generateInitiatorNego() + self.generateMetaData(metaData) + self.generateAPRequest(data)

    def negoexApRequest(self, data, privData):
        # create data from keberos as normal ap request with data from as response and send it to generateAPRequest
        # create data as checksum of all previous packets to send to generateVerify
        apReq = self.generateAPRequest(data)
        checksumtype = _checksum_table[ChecksumTypes.hmac_sha1_96_aes256.value]
        keyServer = Key(Enctype.AES256, 'fb3f5b9cb2e387a5815d57e672978a118c22404938b279bbd4e29e1505cac2c3'.decode('hex'))
        checksumToSend = checksumtype.checksum(keyServer, 25, (privData + apReq).decode('hex')).encode('hex')
        return apReq + self.generateVerify(checksumToSend=checksumToSend)

    def negoexProcess(self):
        return self.generateInitiatorNego() + self.generateMetaData()

    def raiseSequenceNum(self):
        self.sequenceNum += 1
