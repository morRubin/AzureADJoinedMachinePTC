from NegoEx.Packets import Negoex
from NegoEx.Structs import generateMetaDataAsn, splitStructs

from kerberos.krb5 import decrypt_pk_dh, build_as_req_negoEx
from kerberos.PkinitAsn import NegotiationToken
from kerberos.impacketTGS import getKerberosTGS

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

from pyasn1.codec.der.decoder import decode

class NegoExHelper:
    def __init__(self, userCert, certPass, remoteComputer):
        self._userCert = userCert
        self._certPass = certPass
        self._remoteComputer = remoteComputer
        self._p = int('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16)  # safe prime
        self._g = 2
        self._pn = dh.DHParameterNumbers(self._p, self._g)
        self._diffieHellmanParameters = self._pn.parameters(default_backend())
        self._diffieHellmanExchange = self._diffieHellmanParameters, self._diffieHellmanParameters.generate_private_key(), self._pn
        self._nego = Negoex()
        self._asReq = None
        self._dataToSend = None

    def GenerateNegoExKerberosAs(self):
        issuer, self._asReq = build_as_req_negoEx(self._userCert, self._certPass, self._remoteComputer, self._diffieHellmanExchange)
        
        metaData = generateMetaDataAsn(self._remoteComputer, issuer)
        self._dataToSend = self._nego.negoexAsRequest(metaData, self._asReq)
        return self._dataToSend

    def GenerateNegoExKerberosAp(self, response):
        gssAPIData = response['Data'].encode('hex')[16:]
        out = decode(gssAPIData.decode('hex'), asn1Spec=NegotiationToken())[0]['NegTokenResp']['responseToken']
        kerberosASResponse, returnStructs = splitStructs(out.asOctets().encode('hex'), self._nego)
        # data should be parsed to get only challenge
        session_key, cipher, tgtResponse = decrypt_pk_dh(kerberosASResponse.decode('hex'), self._userCert, self._certPass, self._diffieHellmanExchange)
        apReq = getKerberosTGS(cipher, session_key, tgtResponse, self._asReq + kerberosASResponse)
        dataToSend = self._nego.negoexApRequest(apReq, self._dataToSend + ''.join(returnStructs))
        return dataToSend

    def ExtractSubSessionKey(self, response):
        gssAPIData = response['Data'].encode('hex')[16:]
        out = decode(gssAPIData.decode('hex'), asn1Spec=NegotiationToken())[0]['NegTokenResp']['responseToken'].asOctets().encode('hex')
        challenge = out.split('4e45474f45585453')[1]
        # go over 56 bytes and get exchange bytes contains ap response
        decodedApRep = decode(challenge[56*2:].decode('hex'), asn1Spec=SPNEGO_PKINIT())[0]
        encryptedData = decodedApRep['Kerberos']['ApRep']['enc-part']['cipher'].asOctets()
        decryptedData = cipher.decrypt(session_key, 12, encryptedData)
        apReturnKey = decode(decryptedData, asn1Spec=EncAPRepPart())[0]['subkey']['keyvalue'].asOctets()
