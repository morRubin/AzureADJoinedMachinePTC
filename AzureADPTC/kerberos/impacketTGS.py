import datetime
import random
import socket
import struct
import os

from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from six import b
from binascii import unhexlify, hexlify

from impacket.krb5.crypto import _checksum_table, Enctype
from impacket.krb5.constants import KERB_NON_KERB_CKSUM_SALT, ChecksumTypes
from impacket.structure import Structure
from impacket.krb5 import asn1
from impacket.krb5.asn1 import AS_REQ, AP_REQ, TGS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, PA_ENC_TS_ENC, AS_REP, TGS_REP, \
    EncryptedData, Authenticator, EncASRepPart, EncTGSRepPart, seq_set, seq_set_iter, KERB_ERROR_DATA, METHOD_DATA, \
    ETYPE_INFO2, ETYPE_INFO, AP_REP, EncAPRepPart, Ticket as KerberosTicket, AuthorizationData
from impacket.krb5.types import KerberosTime, Principal, Ticket, _asn1_decode, EncryptedData as EncData
from impacket.krb5.gssapi import CheckSumField, GSS_C_DCE_STYLE, GSS_C_MUTUAL_FLAG, GSS_C_REPLAY_FLAG, \
    GSS_C_SEQUENCE_FLAG, GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG
from impacket.krb5 import constants
from impacket.krb5.crypto import Key, _enctype_table, InvalidChecksum
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp, ASN1_OID, asn1encode, ASN1_AID
from impacket import nt_errors, LOG
from random import getrandbits

from AzureADPTC.kerberos.PkinitAsn import SPNEGO_PKINIT, univ, KERB_AD_RESTRICTION_ENTRYS, KRB_FINISHED

from enum import Enum

from AzureADPTC.NegoEx.Structs import LSAP_TOKEN_INFO_INTEGRITY, Pack, GenerateExtensions

def sendReceive(data, host, kdcHost):
    if kdcHost is None:
        targetHost = host
    else:
        targetHost = kdcHost

    messageLen = struct.pack('!i', len(data))

    LOG.debug('Trying to connect to KDC at %s' % targetHost)
    try:
        af, socktype, proto, canonname, sa = socket.getaddrinfo(targetHost, 88, 0, socket.SOCK_STREAM)[0]
        s = socket.socket(af, socktype, proto)
        s.connect(sa)
    except socket.error as e:
        raise socket.error("Connection error (%s:%s)" % (targetHost, 88), e)

    s.sendall(messageLen + data)

    recvDataLen = struct.unpack('!i', s.recv(4))[0]

    r = s.recv(recvDataLen)
    while len(r) < recvDataLen:
        r += s.recv(recvDataLen-len(r))

    try:
        krbError = KerberosError(packet = decoder.decode(r, asn1Spec = KRB_ERROR())[0])
    except:
        return r

    if krbError.getErrorCode() != constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
        raise krbError

    return r

class PrincipalNameType(Enum):
    NT_UNKNOWN        = 0 
    NT_PRINCIPAL      = 1
    NT_SRV_INST       = 2
    NT_SRV_HST        = 3
    NT_SRV_XHST       = 4
    NT_UID            = 5
    NT_X500_PRINCIPAL = 6
    NT_SMTP_NAME      = 7
    NT_ENTERPRISE     = 10
    NT_AAD            = -128  

class PrincipalModified(object):
    """The principal's value can be supplied as:
* a single string
* a sequence containing a sequence of component strings and a realm string
* a sequence whose first n-1 elemeents are component strings and whose last
  component is the realm
If the value contains no realm, then default_realm will be used."""
    def __init__(self, value=None, default_realm=None, type=None):
        self.type = PrincipalNameType.NT_UNKNOWN
        self.components = []
        self.realm = None

        if value is None:
            return

        try:               # Python 2
            if isinstance(value, unicode):
                value = value.encode('utf-8')
        except NameError:  # Python 3
            if isinstance(value, bytes):
                value = value.decode('utf-8')

        if isinstance(value, Principal):
            self.type = value.type
            self.components = value.components[:]
            self.realm = value.realm
        elif isinstance(value, str):
            m = re.match(r'((?:[^\\]|\\.)+?)(@((?:[^\\@]|\\.)+))?$', value)
            if not m:
                raise KerberosException("invalid principal syntax")

            def unquote_component(comp):
                return re.sub(r'\\(.)', r'\1', comp)

            if m.group(2) is not None:
                self.realm = unquote_component(m.group(3))
            else:
                self.realm = default_realm

            self.components = [
                unquote_component(qc)
                for qc in re.findall(r'(?:[^\\/]|\\.)+', m.group(1))]
        elif len(value) == 2:
            self.components = value[0]
            self.realm = value[-1]
            if isinstance(self.components, str):
                self.components = [self.components]
        elif len(value) >= 2:
            self.components = value[0:-1]
            self.realm = value[-1]
        else:
            raise KerberosException("invalid principal value")

        if type is not None:
            self.type = type

    def __eq__(self, other):
        if isinstance (other, str):
            other = Principal (other)

        return (self.type == PrincipalNameType.NT_UNKNOWN.value or
                other.type == PrincipalNameType.NT_UNKNOWN.value or
                self.type == other.type) and all (map (lambda a, b: a == b, self.components, other.components)) and \
               self.realm == other.realm

    def __str__(self):
        import re
        def quote_component(comp):
            return re.sub(r'([\\/@])', r'\\\1', comp)

        ret = "/".join([quote_component(c) for c in self.components])
        if self.realm is not None:
            ret += "@" + self.realm

        return ret

    def __repr__(self):
        return "Principal((" + repr(self.components) + ", " + \
               repr(self.realm) + "), t=" + str(self.type) + ")"

    def from_asn1(self, data, realm_component, name_component):
        name = data.getComponentByName(name_component)
        self.type = PrincipalNameType(
            name.getComponentByName('name-type')).value
        self.components = [
            str(c) for c in name.getComponentByName('name-string')]
        self.realm = str(data.getComponentByName(realm_component))
        return self

    def components_to_asn1(self, name):
        name.setComponentByName('name-type', int(self.type))
        strings = name.setComponentByName('name-string'
                                          ).getComponentByName('name-string')
        for i, c in enumerate(self.components):
            strings.setComponentByPosition(i, c)

        return name

class EncryptedData(object):
    def __init__(self):
        self.etype = None
        self.ciphertext = None

    def from_asn1(self, data):
        data = _asn1_decode(data, asn1.EncryptedData())
        self.etype = constants.EncryptionTypes(data.getComponentByName('etype')).value
        self.ciphertext = str(data.getComponentByName('cipher'))
        return self

    def to_asn1(self, component):
        component.setComponentByName('etype', int(self.etype))
        component.setComponentByName('cipher', self.ciphertext)
        return component

class Ticket(object):
    def __init__(self):
        # This is the kerberos version, not the service principal key
        # version number.
        self.tkt_vno = None
        self.service_principal = None
        self.encrypted_part = None

    def from_asn1(self, data):
        data = _asn1_decode(data, asn1.Ticket())
        self.tkt_vno = int(data.getComponentByName('tkt-vno'))
        self.service_principal = PrincipalModified()
        self.service_principal.from_asn1(data, 'realm', 'sname')
        self.encrypted_part = EncryptedData()
        self.encrypted_part.from_asn1(data.getComponentByName('enc-part'))
        return self

    def to_asn1(self, component):
        component.setComponentByName('tkt-vno', 5)
        component.setComponentByName('realm', self.service_principal.realm)
        asn1.seq_set(component, 'sname',
                     self.service_principal.components_to_asn1)
        asn1.seq_set(component, 'enc-part', self.encrypted_part.to_asn1)

        return component

    def __str__(self):
        return "<Ticket for %s vno %s>" % (str(self.service_principal), str(self.encrypted_part.kvno))


def getKerberosTGS(cipher, sessionKey, tgtResponse, gssAPIChecksumBuffer):

    apReqNegoEx = SPNEGO_PKINIT()
    apReqNegoEx['kerberos-v5'] = '1.3.6.1.5.2.7'
    apReqNegoEx['null'] = univ.Boolean(True)
    
    # Extract the ticket from the TGT
    ticket = Ticket() # should be -128 name-type
    ticket.from_asn1(tgtResponse['ticket'])

    apReqNegoEx['Kerberos']['ApReq']['pvno'] = 5
    apReqNegoEx['Kerberos']['ApReq']['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = list()
    opts.append( constants.KDCOptions.forwarded.value )
    apReqNegoEx['Kerberos']['ApReq']['ap-options'] =  constants.encodeFlags(opts)
    seq_set(apReqNegoEx['Kerberos']['ApReq'],'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = tgtResponse['crealm'].asOctets()

    clientName = PrincipalModified()
    clientName.from_asn1( tgtResponse, 'crealm', 'cname')
    
    seq_set(authenticator, 'cname', clientName.components_to_asn1)

    now = datetime.datetime.utcnow()
    authenticator['cusec'] =  2 #now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    authenticator['cksum']['cksumtype'] = 0x8003

    chkField = CheckSumField()
    chkField['Lgth'] = 16

    # GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | GSS_C_EXTENDED_ERROR_FLAG
    chkField['Flags'] = 16418

    subKey = 'FB3F5B9CB2E387A5815D57E672978A118C22404938B279BBD4E29E1505CAC2C3'.decode('hex')
    checksumtype = _checksum_table[ChecksumTypes.hmac_sha1_96_aes256.value]
    keyServer = Key(Enctype.AES256, subKey)

    kerbFinished = KRB_FINISHED()
    kerbFinished['gss-mic']['cksumtype'] = 16
    kerbFinished['gss-mic']['checksum'] = checksumtype.checksum(keyServer, 41, gssAPIChecksumBuffer.decode('hex'))
    
    authenticator['cksum']['checksum'] = chkField.getData() + (GenerateExtensions(encoder.encode(kerbFinished).encode('hex'))).decode('hex')
    
    authenticator['subkey']['keytype'] = 18
    authenticator['subkey']['keyvalue'] = subKey
    
    authenticator['seq-number'] = 682437742

    tokenIntegrity = LSAP_TOKEN_INFO_INTEGRITY()
    tokenIntegrity.Flags = 1
    tokenIntegrity.MachineID = '7e303fffe6bff25146addca4fbddf1b94f1634178eb4528fb2731c669ca23cde'.decode('hex')
    tokenIntegrity.TokenIL = int('2000', 16)

    RESTRICTION_ENTRY = KERB_AD_RESTRICTION_ENTRYS()  
    RESTRICTION_ENTRY[0]['restriction-type'] = 0 # const
    RESTRICTION_ENTRY[0]['restriction'] = Pack(tokenIntegrity).decode('hex')

    KERB_AUTH_DATA_TOKEN_RESTRICTIONS = AuthorizationData()
    KERB_AUTH_DATA_TOKEN_RESTRICTIONS[0]['ad-type'] = 141
    KERB_AUTH_DATA_TOKEN_RESTRICTIONS[0]['ad-data'] = encoder.encode(RESTRICTION_ENTRY)

    # AD_IF_RELEVANT
    authenticator['authorization-data'][0]['ad-type'] = 1
    authenticator['authorization-data'][0]['ad-data'] = encoder.encode(KERB_AUTH_DATA_TOKEN_RESTRICTIONS)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 7
    # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
    # TGS authenticator subkey), encrypted with the TGS session
    # key (Section 5.5.1)

    ## should be key usage 11

    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReqNegoEx['Kerberos']['ApReq']['authenticator']['etype'] = cipher.enctype
    apReqNegoEx['Kerberos']['ApReq']['authenticator']['cipher'] = encryptedEncodedAuthenticator

    data = encoder.encode(apReqNegoEx).encode('hex')
    data = data[:4] + "{0:0{1}x}".format(int(data[4:8],16) - 1, 4) + data[8:26] + '00' + data[30:]

    return data
    
