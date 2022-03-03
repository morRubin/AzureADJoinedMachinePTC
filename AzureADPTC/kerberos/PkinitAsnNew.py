from minikerberos.protocol.asn1_structs import AS_REQ, AS_REP, AP_REQ
from asn1crypto import core
from pyasn1.type import univ
from pyasn1.type.namedtype import NamedType, NamedTypes
from pyasn1.type.tag import tagFormatSimple, tagClassApplication, Tag
from pyasn1.type.univ import Sequence


class SequenceOfObjectIdentifier(core.SequenceOf):
    _child_spec = core.ObjectIdentifier


class negState(core.Enumerated):
    _map = {
        0: 'accept-completed',
        1: 'accept-incomplete',
        2: 'reject',
        3: 'request-mic'
    }


class NegTokenResp(core.Sequence):
    _fields = [
        ('negState', negState, {'tag_type': 'explicit', 'tag': 0}),
        ('supportedMech', core.ObjectIdentifier, {'tag_type': 'explicit', 'tag': 1}),
        ('responseToken', core.OctetString, {'tag_type': 'explicit', 'tag': 2}),
        ('mechListMIC', core.OctetString, {'tag_type': 'explicit', 'tag': 3, 'optional': True})
    ]


class ContextFlags(core.BitString):
    _map = {
        0: 'delegFlag',
        1: 'mutualFlag',
        2: 'replayFlag',
        3: 'sequenceFlag',
        4: 'anonFlag',
        5: 'confFlag',
        6: 'integFlag'
    }


class NegTokenInit(core.Sequence):
    _fields = [
        ('mechTypes', SequenceOfObjectIdentifier, {'tag_type': 'explicit', 'tag': 0}),
        ('reqFlags', ContextFlags, {'tag_type': 'explicit', 'tag': 1}),
        ('mechToken', core.OctetString, {'tag_type': 'explicit', 'tag': 2}),
        ('mechListMIC', core.OctetString, {'tag_type': 'explicit', 'tag': 3})
    ]


class NegotiationToken(core.Choice):
    _alternatives = [
        ('NegTokenInit', NegTokenInit, {'tag_type': 'explicit', 'tag': 0}),
        ('NegTokenResp', NegTokenResp, {'tag_type': 'explicit', 'tag': 1})
    ]


class SPNEGO_PKINIT_AP_REQ(core.Sequence):
    class_ = 1
    tag = 0
    _fields = [
        ('kerberos-v5', core.ObjectIdentifier),
        ('null', core.Any),
        ('Kerberos', AP_REQ),
    ]


class SPNEGO_PKINIT_REP(core.Sequence):
    class_ = 1
    tag = 0
    _fields = [
        ('kerberos-v5', core.ObjectIdentifier),
        ('null', core.Any),
        ('Kerberos', AS_REQ),
    ]


class SPNEGO_PKINIT_AS_REP(core.Sequence):
    class_ = 1
    tag = 0
    _fields = [
        ('kerberos-v5', core.ObjectIdentifier),
        ('null', core.Any),
        ('Kerberos', AS_REP),
    ]
