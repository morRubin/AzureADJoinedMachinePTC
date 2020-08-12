import pyasn1.type as asn
from pyasn1.type import tag, namedtype, univ, constraint, char, useful
from impacket.krb5.asn1 import AP_REQ, AP_REP

from AzureADPTC.kerberos.krb5 import *

import AzureADPTC.rfcAsns.rfc5280 as rfc5280
import AzureADPTC.rfcAsns.rfc5652 as rfc5652
import AzureADPTC.rfcAsns.rfc2315 as rfc2315


def _c(n, t):
    return t.clone(tagSet=t.tagSet + Tag(tagClassContext, tagFormatSimple, n))

def _sequence_optional_component(name, tag_value, type, **subkwargs):
    return asn.namedtype.OptionalNamedType(name, type.subtype(
        explicitTag=asn.tag.Tag(asn.tag.tagClassContext, asn.tag.tagFormatSimple,
                            tag_value),
        **subkwargs))

def _msg_type_component(tag_value, values):
    c = asn.constraint.ConstraintsUnion(
        *(asn.constraint.SingleValueConstraint(int(v)) for v in values))
    return _sequence_component('msg-type', tag_value, asn.univ.Integer(),
                               subtypeSpec=c)

def _application_component(name, tag_value, type, **subkwargs):
    return asn.namedtype.NamedType(name, type.subtype(
        explicitTag=asn.tag.Tag(asn.tag.tagClassApplication, asn.tag.tagFormatSimple,
                            tag_value),
        **subkwargs))

def _sequence_component(name, tag_value, type, **subkwargs):
    return asn.namedtype.NamedType(name, type.subtype(
        explicitTag=asn.tag.Tag(asn.tag.tagClassContext, asn.tag.tagFormatSimple,
                            tag_value),
        **subkwargs))

def _application_tag(tag_value):
    return asn.univ.Sequence.tagSet.tagExplicitly(
        asn.tag.Tag(asn.tag.tagClassApplication, asn.tag.tagFormatConstructed,
                int(tag_value)))

def application(n):
    return Sequence.tagSet + Tag(tagClassApplication, tagFormatSimple, n)

class Microseconds(Integer): pass

class KerberosString(GeneralString): pass

class Realm(KerberosString): pass

class PrincipalName(Sequence):
    componentType = NamedTypes(
        _sequence_component('name-type', 0, Integer()),
        _sequence_component('name-string', 1, SequenceOf(componentType=KerberosString())))

class KerberosTime(GeneralizedTime): pass

class HostAddress(Sequence):
    componentType = NamedTypes(
        _sequence_component('addr-type', 0, Integer()),
        _sequence_component('address', 1, OctetString()))

class HostAddresses(SequenceOf):
    componentType = HostAddress()

class AuthorizationData(SequenceOf):
    componentType = Sequence(componentType=NamedTypes(
            _sequence_component('ad-type', 0, Integer()),
            _sequence_component('ad-data', 1, OctetString())))

class PAData(Sequence):
    componentType = NamedTypes(
        _sequence_component('padata-type', 1, Integer()),
        _sequence_component('padata-value', 2, OctetString()))

class NegoPAData(Sequence):
    componentType = NamedTypes(
        _sequence_component('value', 0, univ.Any()))

class KerberosFlags(BitString): pass

class EncryptedData(Sequence):
    componentType = NamedTypes(
        _sequence_component('etype', 0, Integer()),
        _sequence_optional_component('kvno', 1, Integer()),
        _sequence_component('cipher', 2, OctetString()))

class EncryptionKey(Sequence):
    componentType = NamedTypes(
        _sequence_component('keytype', 0, Integer()),
        _sequence_component('keyvalue', 1, OctetString()))    

class CheckSum(Sequence):
    componentType = NamedTypes(
        _sequence_component('cksumtype', 0, Integer()),
        _sequence_component('checksum', 1, OctetString()))

class Ticket(Sequence):
    tagSet = application(1)
    componentType = NamedTypes(
        NamedType('tkt-vno', _c(0, Integer())),
        NamedType('realm', _c(1, Realm())),
        NamedType('sname', _c(2, PrincipalName())),
        NamedType('enc-part', _c(3, EncryptedData())))

class APOptions(KerberosFlags): pass

class APReq(Sequence):
    tagSet = application(14)
    componentType = NamedTypes(
        NamedType('pvno', _c(0, Integer())),
        NamedType('msg-type', _c(1, Integer())),
        NamedType('ap-options', _c(2, APOptions())),
        NamedType('ticket', _c(3, Ticket())),
        NamedType('authenticator', _c(4, EncryptedData())))

class Authenticator(Sequence):
    tagSet = application(2)
    componentType = NamedTypes(
        NamedType('authenticator-vno', _c(0, Integer())),
        NamedType('crealm', _c(1, Realm())),
        NamedType('cname', _c(2, PrincipalName())),
        OptionalNamedType('cksum', _c(3, CheckSum())),
        NamedType('cusec', _c(4, Microseconds())),
        NamedType('ctime', _c(5, KerberosTime())),
        OptionalNamedType('subkey', _c(6, EncryptionKey())),
        OptionalNamedType('seq-number', _c(7, Integer())),
        OptionalNamedType('authorization-data', _c(8, AuthorizationData())))

class KDCOptions(KerberosFlags): pass

class KdcReqBody(Sequence):
    componentType = NamedTypes(
        _sequence_component('kdc-options', 0, KDCOptions()),
        _sequence_optional_component('cname', 1, PrincipalName()),
        _sequence_component('realm', 2, Realm()),
        _sequence_optional_component('sname', 3, PrincipalName()),
        _sequence_optional_component('from', 4, KerberosTime()),
        _sequence_component('till', 5, KerberosTime()),
        _sequence_optional_component('rtime', 6, KerberosTime()),
        _sequence_component('nonce', 7, Integer()),
        _sequence_component('etype', 8, SequenceOf(componentType=Integer())),
        _sequence_optional_component('addresses', 9, HostAddresses()),
        _sequence_optional_component('enc-authorization-data', 10, EncryptedData()),
        _sequence_optional_component('additional-tickets', 11, SequenceOf(componentType=Ticket())))

class KdcReq(Sequence):
    componentType = NamedTypes(
        _sequence_component('pvno', 1, Integer()),
        _sequence_component('msg-type', 2, Integer()),
        _sequence_component('padata', 3, SequenceOf(componentType=PAData())),
        _sequence_component('req-body', 4, KdcReqBody()))

class TicketFlags(KerberosFlags): pass

class AsReq(KdcReq):
    tagSet = application(10)

class TgsReq(KdcReq):
    tagSet = application(12)

class KdcRep(Sequence):
    componentType = NamedTypes(
        NamedType('pvno', _c(0, Integer())),
        NamedType('msg-type', _c(1, Integer())),
        OptionalNamedType('padata', _c(2, SequenceOf(componentType=PAData()))),
        NamedType('crealm', _c(3, Realm())),
        NamedType('cname', _c(4, PrincipalName())),
        NamedType('ticket', _c(5, Ticket())),
        NamedType('enc-part', _c(6, EncryptedData())))

class AsRep(KdcRep):
    tagSet = application(11)

class TgsRep(KdcRep):
    tagSet = application(13)

class LastReq(SequenceOf):
    componentType = Sequence(componentType=NamedTypes(
            NamedType('lr-type', _c(0, Integer())),
            NamedType('lr-value', _c(1, KerberosTime()))))

class PaEncTimestamp(EncryptedData): pass

class PaEncTsEnc(Sequence):
    componentType = NamedTypes(
        NamedType('patimestamp', _c(0, KerberosTime())),
        NamedType('pausec', _c(1, Microseconds())))

class EncKDCRepPart(Sequence):
    componentType = NamedTypes(
        NamedType('key', _c(0, EncryptionKey())),
        NamedType('last-req', _c(1, LastReq())),
        NamedType('nonce', _c(2, Integer())),
        OptionalNamedType('key-expiration', _c(3, KerberosTime())),
        NamedType('flags', _c(4, TicketFlags())),
        NamedType('authtime', _c(5, KerberosTime())),
        OptionalNamedType('starttime', _c(6, KerberosTime())),
        NamedType('endtime', _c(7, KerberosTime())),
        OptionalNamedType('renew-till', _c(8, KerberosTime())),
        NamedType('srealm', _c(9, Realm())),
        NamedType('sname', _c(10, PrincipalName())),
        OptionalNamedType('caddr', _c(11, HostAddresses())))

class EncASRepPart(EncKDCRepPart):
    tagSet = application(25)

class EncTGSRepPart(EncKDCRepPart):
    tagSet = application(26)

class EncAPRepPart(Sequence):
    tagSet = application(27)
    componentType = NamedTypes(
        _sequence_component('ctime', 0, KerberosTime()),
        _sequence_component('cusec', 1, Microseconds()),
        _sequence_optional_component('subkey', 2, EncryptionKey()),
        _sequence_optional_component('seq-number', 3, Integer())
    )

class TransitedEncoding(Sequence):
    componentType = NamedTypes(
        NamedType('tr-type', _c(0, Integer())),
        NamedType('contents', _c(1, OctetString())))

class EncTicketPart(Sequence):
    tagSet = application(3)
    componentType = NamedTypes(
        NamedType('flags', _c(0, TicketFlags())),
        NamedType('key', _c(1, EncryptionKey())),
        NamedType('crealm', _c(2, Realm())),
        NamedType('cname', _c(3, PrincipalName())),
        NamedType('transited', _c(4, TransitedEncoding())),
        NamedType('authtime', _c(5, KerberosTime())),
        OptionalNamedType('starttime', _c(6, KerberosTime())),
        NamedType('endtime', _c(7, KerberosTime())),
        OptionalNamedType('renew-till', _c(8, KerberosTime())),
        OptionalNamedType('caddr', _c(9, HostAddresses())),
        OptionalNamedType('authorization-data', _c(10, AuthorizationData())))

class KerbPaPacRequest(Sequence):
    componentType = NamedTypes(
        NamedType('include-pac', _c(0, Boolean())))

class Microseconds(Integer): pass


class KerberosString(GeneralString): pass


class Realm(KerberosString): pass


class PrincipalName(Sequence):
    componentType = NamedTypes(
        _sequence_component('name-type', 0, Integer()),
        _sequence_component('name-string', 1, SequenceOf(componentType=KerberosString())))


class KerberosTime(GeneralizedTime): pass


class HostAddress(Sequence):
    componentType = NamedTypes(
        _sequence_component('addr-type', 0, Integer()),
        _sequence_component('address', 1, OctetString()))


class HostAddresses(univ.SequenceOf):
    componentType = HostAddress()


class KerberosFlags(univ.BitString):
    pass


class KDCOptions(KerberosFlags):
    pass


class KerberosString(char.GeneralString):
    pass


class Realm(KerberosString):
    pass




class KerberosTime(useful.GeneralizedTime):
    pass

class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('etype', 0, univ.Integer()),
        _sequence_optional_component('kvno', 1, univ.Integer()),
        _sequence_component('cipher', 2, univ.OctetString())
    )


class Ticket(univ.Sequence):
    tagSet = _application_tag(1)
    componentType = namedtype.NamedTypes(
        _sequence_component('tkt-vno', 0, univ.Integer()),
        _sequence_component("realm", 1, Realm()),
        _sequence_component("sname", 2, PrincipalName()),
        _sequence_component("enc-part", 3, EncryptedData())
    )


class DHNonce(univ.OctetString):
    pass


class TrustedCA(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_optional_component('subjectName', 0, univ.OctetString()),
        _sequence_optional_component('issuerAndSerialNumber', 1, univ.OctetString()),
        _sequence_optional_component('subjectKeyIdentifier', 2, univ.OctetString())
    )


class AlgorithmIdentifierParams(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('param1', univ.Integer()),
        namedtype.NamedType('param2', univ.Integer()),
        namedtype.NamedType('param3', univ.Integer())
    )


class subjectPublicKey(univ.Sequence):
    tagSet = univ.BitString.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassContext, tag.tagCategoryExplicit, 1)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('value', univ.Integer())
    )


algorithmIdentifierMap = {}


class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Any())
    )


class SubjectPublicKeyInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', AlgorithmIdentifier()),
        namedtype.NamedType('subjectPublicKey', univ.Any())
    )


class PKAuthenticator(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('cusec', 0, univ.Integer()),
        _sequence_component('ctime', 1, KerberosTime()),
        _sequence_component('nonce', 2, univ.Integer()),
        _sequence_optional_component('paChecksum', 3, univ.OctetString())
    )

class clientDHNonce(univ.OctetString):
    pass

class AuthPack(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('pkAuthenticator', 0, PKAuthenticator()),
        _sequence_optional_component('clientPublicValue', 1, SubjectPublicKeyInfo()),
        _sequence_optional_component('supportedCMSTypes', 2,
                                     univ.SequenceOf(componentType=AlgorithmIdentifier())),
        _sequence_optional_component('clientDHNonce', 3, clientDHNonce())
    )


class AuthPack_Identifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('AuthPack', AuthPack())
    )


class signedAuthPack(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id-pkinit-authData', univ.ObjectIdentifier()),
        _sequence_component('id-pkinit-authData-value', 0, univ.OctetString())#AuthPack_Identifier())
    )


class CMSVersion(univ.Integer):
    pass


class AttributeValue(univ.Any):
    pass


class SignatureValue(univ.OctetString):
    pass


cmsAttributesMap = {}


class Attribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attrType', univ.ObjectIdentifier()),
        namedtype.NamedType('attrValues', univ.SetOf(componentType=AttributeValue()))
    )


certificateAttributesMap = {}


class AttributeTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Any())
    )


class RelativeDistinguishedName(univ.SetOf):
    componentType = AttributeTypeAndValue()


class RDNSequence(univ.SequenceOf):
    componentType = univ.SetOf(componentType=AttributeTypeAndValue())


class Name(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('rdnSequence',
                            univ.SequenceOf(componentType=univ.SetOf(componentType=AttributeTypeAndValue())))
    )


class IssuerAndSerialNumber(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuer', Name()),
        namedtype.NamedType('serialNumber', univ.Integer())
    )


class IssuerAndSerialNumber1(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuer', univ.SequenceOf(componentType=univ.SetOf(componentType=AttributeTypeAndValue()))),
        namedtype.NamedType('serialNumber', univ.Integer())
    )


class SignerIdentifier(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuerAndSerialNumber', IssuerAndSerialNumber()),
        _sequence_component('subjectKeyIdentifier', 0, univ.OctetString())
    )


class DigestAlgorithmIdentifiers(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('first', AlgorithmIdentifier())
    )


class SignedAttributes(univ.SetOf):
    pass


SignedAttributes.componentType = Attribute()

class SignedAttrs(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('1', Attribute()),
        namedtype.NamedType('2', Attribute())
        )

class SignerInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', CMSVersion()),
        namedtype.NamedType('sid', SignerIdentifier()),
        namedtype.NamedType('digestAlgorithm', AlgorithmIdentifier()),
        # DigestAlgorithmIdentifier
        _sequence_optional_component('signedAttrs', 0, univ.Any()),
        # SignedAttributes @ shouldnt be set, but set in documentation
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),  # SignatureAlgorithmIdentifier
        namedtype.NamedType('signature', SignatureValue()),
        _sequence_optional_component('unsignedAttrs', 1, univ.SetOf(componentType=Attribute()))  # UnsignedAttributes
    )


class SignedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', CMSVersion()),
        namedtype.NamedType('digestAlgorithms', univ.SetOf(componentType=AlgorithmIdentifier())),
        # DigestAlgorithmIdentifier
        namedtype.NamedType('encapContentInfo', signedAuthPack()),  # EncapsulatedContentInfo
        _sequence_optional_component('certificates', 0, univ.Any()),  # CertificateSet NEED CHANGE
        _sequence_optional_component('crls ', 1, univ.Integer()),  # RevocationInfoChoices NEED CHANGE
        namedtype.NamedType('signerInfos', univ.SetOf(componentType=SignerInfo()))  #
    )

class PA_DATAval(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('signed-data', SignedData())
    )

class SignedAuthPack(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('id-signedData', univ.ObjectIdentifier()),
        _sequence_component('content', 0, SignedData())
    )

class PA_DATA(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('padata-type', 1, univ.Integer()),
        namedtype.NamedType('padata-value', SignedAuthPack())
    )

class PA_PK_AS_REQ(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('signedAuthPack', 0 ,univ.Any()))

class DHRepInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('dhSignedData', _c(0 ,univ.Any())),
        namedtype.OptionalNamedType('encKeyPack', _c(1 ,DHNonce())))

class OtherRevocationInfoFormat(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('otherRevInfoFormat', univ.ObjectIdentifier()),
        namedtype.NamedType('otherRevInfo', univ.Any())
        )
   
class RevocationInfoChoice(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('crl', rfc5280.CertificateList()),
        namedtype.NamedType('other', _c(1 ,OtherRevocationInfoFormat()))
        )

class OriginatorInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certs', _c(0 ,univ.SetOf(componentType=rfc5652.CertificateChoices()))),
        namedtype.OptionalNamedType('crls', _c(1 ,univ.SetOf(componentType=RevocationInfoChoice())))
        )

class EncryptedContentInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        NamedType('contentType', rfc5652.ContentType()),
        NamedType('contentEncryptionAlgorithm', rfc2315.ContentEncryptionAlgorithmIdentifier()),
        namedtype.OptionalNamedType('encryptedContent', _c(1, univ.OctetString()))
        )

class EncryptedContentInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('contentType', rfc5652.ContentType()),
        namedtype.NamedType('contentEncryptionAlgorithm', rfc2315.ContentEncryptionAlgorithmIdentifier()),
        namedtype.OptionalNamedType(
            'encryptedContent', univ.OctetString().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
            ))
    )

class EnvelopedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        NamedType('CMSVersion', univ.Integer()),
        namedtype.OptionalNamedType('originatorInfo', _c(0, OriginatorInfo())),
        NamedType('recipientInfos', univ.SetOf(componentType=rfc2315.RecipientInfo())),
        NamedType('encryptedContentInfo', EncryptedContentInfo()),
        namedtype.OptionalNamedType('unprotectedAttrs', _c(1, univ.SetOf(componentType=Attribute())))
        )

class encKeyPack(univ.Sequence):
    componentType = namedtype.NamedTypes(
        NamedType('ContentType', univ.ObjectIdentifier()),
        NamedType('ContentInfo', _c(0, EnvelopedData()))
        )

class CheckSum(Sequence):
    componentType = NamedTypes(
        _sequence_component('cksumtype', 0, Integer()),
        _sequence_component('checksum', 1, OctetString()))

class EncryptionKey(Sequence):
    componentType = NamedTypes(
        NamedType('keytype', _c(0, univ.Integer())),
        NamedType('keyvalue', _c(1, univ.OctetString()))) 

class ReplyKeyPack(univ.Sequence):
    componentType = namedtype.NamedTypes(
        NamedType('replyKey', _c(0, EncryptionKey())),
        NamedType('asChecksum', _c(1, CheckSum()))
        )

class AS_REP_Padata(univ.Choice):
    componentType = namedtype.NamedTypes(
        _sequence_component('DHRepInfo', 0, DHRepInfo()),
        _sequence_component('encKeyPack', 1 ,univ.OctetString())
        )

class SPNEGO_CHALLENGE_AS_RESPONSE(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('DHRepInfo', 0, DHRepInfo()),
        _sequence_component('encKeyPack', 1 ,univ.OctetString())
        )

class PAData2(Sequence):
    componentType = NamedTypes(
        NamedType('padata-type', _c(1, Integer())),
        NamedType('padata-value', _c(2, OctetString())))

def application(n):
    return Sequence.tagSet + Tag(tagClassApplication, tagFormatSimple, n)

class KDCDHKeyInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('subjectPublicKey', 0, univ.BitString()),
        _sequence_component('nonce', 1 ,univ.Integer()),
        _sequence_optional_component('dhKeyExpiration', 2 ,KerberosTime())
        )

class PA_PK_AS_REP(univ.Sequence):
    tagSet = application(11)
    componentType = NamedTypes(
        _sequence_component('pvno', 0, Integer()),
        _sequence_component('msg-type', 1, Integer()),
        _sequence_optional_component('padata', 2, SequenceOf(componentType=PAData2())),
        _sequence_component('crealm', 3, Realm()),
        _sequence_component('cname', 4, PrincipalName()),
        _sequence_component('ticket', 5, Ticket()),
        _sequence_component('enc-part', 6, EncryptedData()))

class SPNEGO_PKINIT_REP(univ.Sequence):
    tagSet = Sequence.tagSet.tagImplicitly(
        Tag(tagClassApplication, tagFormatSimple, 0))
    componentType = NamedTypes(
        NamedType('kerberos-v5', univ.ObjectIdentifier('1.3.6.1.5.2.7')),
        NamedType('null', univ.Any()),
        NamedType('Kerberos', PA_PK_AS_REP()))

class NegoExKerberos(univ.Choice):
    componentType = NamedTypes(
        NamedType('ApReq', AP_REQ()),
        NamedType('ApRep', AP_REP()),
        NamedType('AsReq', AsReq())
        )

class SPNEGO_PKINIT(univ.Sequence):
    tagSet = Sequence.tagSet.tagImplicitly(
        Tag(tagClassApplication, tagFormatSimple, 0))
    componentType = NamedTypes(
        NamedType('kerberos-v5', univ.ObjectIdentifier('1.3.6.1.5.2.7')),
        NamedType('null', univ.Any()),
        NamedType('Kerberos', NegoExKerberos()))

class MECHTYPES(univ.Sequence):
    componentType = NamedTypes(
        NamedType('1', univ.ObjectIdentifier()),
        #NamedType('2', univ.ObjectIdentifier())
        )

class NEGTOKENINIT(univ.Sequence):
    componentType = NamedTypes(
        _sequence_component('mechTypes', 0, univ.SequenceOf(univ.ObjectIdentifier())),
        _sequence_component('SpNego', 2 ,univ.OctetString())
        )

class SPNEGO_SECURITYBLOB(univ.Sequence):
    tagSet = univ.Any.tagSet.tagImplicitly(
        Tag(tagClassApplication, tagFormatSimple, 0))
    componentType = NamedTypes(
        NamedType('Oid', univ.ObjectIdentifier()),
        _sequence_component('SimpleProtectedNego', 0 ,NEGTOKENINIT())
        )

class SPNEGO_SECURITYBLOB_RESONSE(univ.Sequence):
    componentType = NamedTypes(
        _sequence_component('type', 0, univ.Integer()),
        _sequence_component('mechType', 1 ,univ.ObjectIdentifier()),
        _sequence_component('SimpleProtectedNego', 2 ,univ.OctetString())
        )

class negState(univ.Enumerated):
    namedValues = asn.namedval.NamedValues(
        ('accept-completed', 0),
        ('accept-incomplete', 1),
        ('reject', 2),
        ('request-mic', 3)
    )

class NegTokenResp(univ.Sequence):
    componentType = NamedTypes(
        _sequence_optional_component('negState', 0, negState()),
        _sequence_optional_component('supportedMech', 1 ,univ.ObjectIdentifier()),
        _sequence_optional_component('responseToken', 2 ,univ.OctetString()),
        _sequence_optional_component('mechListMIC', 3 ,univ.OctetString())
        )

class ContextFlags(univ.BitString):
    namedValues = asn.namedval.NamedValues(
        ('delegFlag', 0),
        ('mutualFlag', 1),
        ('replayFlag', 2),
        ('sequenceFlag', 3),
        ('anonFlag', 4),
        ('confFlag', 5),
        ('integFlag', 6)        
    )

class NegTokenInit(univ.Sequence):
    componentType = NamedTypes(
        _sequence_component('mechTypes', 0, univ.SequenceOf(univ.ObjectIdentifier())),
        _sequence_optional_component('reqFlags', 1 ,ContextFlags()),
        _sequence_optional_component('mechToken', 2 ,univ.OctetString()),
        _sequence_optional_component('mechListMIC', 3 ,univ.OctetString())
        )

class NegotiationToken(univ.Choice):
    componentType = NamedTypes(
        _sequence_component('negTokenInit', 0, NegTokenInit()),
        _sequence_component('NegTokenResp', 1 ,NegTokenResp())
        )

class DHParameters(univ.Sequence):
    componentType = NamedTypes(
        NamedType('longprime', univ.Integer()),
        NamedType('generator', univ.Integer())
        )

class KERB_AD_RESTRICTION_ENTRY(univ.Sequence):
    componentType = NamedTypes(
        _sequence_component('restriction-type', 0, univ.Integer()),
        _sequence_component('restriction', 1, univ.OctetString())
        )
    
class KERB_AD_RESTRICTION_ENTRYS(univ.SequenceOf):
    componentType = KERB_AD_RESTRICTION_ENTRY()

class KRB_FINISHED(univ.Sequence):
    componentType = NamedTypes(
        _sequence_component('gss-mic', 1, CheckSum())
        )
