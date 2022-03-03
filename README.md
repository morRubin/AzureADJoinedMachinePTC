# AzureADJoinedMachine
A tool to run PSEXEC over NegoEX protocol against Azure AD joined machine

## Installation
The code is compatible with Python 3.6+
Clone the repository from GitHub, install the dependencies and you should be good to go

```bash
https://github.com/morRubin/AzureADJoinedMachinePTC
pip3 install impacket minikerberos cryptography==3.1.1 pyasn1
```

## Usage

```
Main.py [-h] --usercert USERCERT --certpass CERTPASS --remoteip
               REMOTEIP
```

## Example

```
Main.py --usercert "Gadmin.pfx" --certpass mor --remoteip 192.168.1.2
```

## License
MIT

## Credits
* [Benjamin Delpy](https://twitter.com/gentilkiwi) for implementing everything in [kekeo](https://github.com/gentilkiwi/kekeo)
* [SkelSec](https://twitter.com/skelsec) for [minikerberos](https://github.com/skelsec/minikerberos/tree/master/minikerberos)
* Alberto Solino and the team at SecureAuthCorp for [impacket](https://github.com/SecureAuthCorp/impacket)
* [Dirk Jan](https://twitter.com/_dirkjan) for implementing PKINIT on Pyhthon3 [PKINITtools](https://github.com/dirkjanm/PKINITtools)