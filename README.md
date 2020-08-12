# AzureADJoinedMachine

## Requirements

* Python 2.7
* PythonForWindows
* Impacket
* Smbprotocol

## Usage

```
Main.py [-h] --usercert USERCERT --certpass CERTPASS --remoteip
               REMOTEIP
```

## Example

```
Main.py --usercert "Gadmin.pfx" --certpass mor --remoteip 192.168.1.2
```

Part of the Kerberos functionality and SMB warrper for PSEXEC taken from Impacket
