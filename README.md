# JMove
Lateral Movement within Windows environments

JMove is a PowerShell tool that is designed to aid in lateral movement within a Windows environment. 

This tool enables you to use new credentials, such as usernames and passwords or hashes or tickets, to perform pass-the-password, pass-the-hash, or pass-the-ticket actions. 

The tool can handle both domain or local credentials, providing a versatile solution for network penetration testing. 

Once the credential material is provided, JMove will first enumerate Active Directory (AD) for servers or workstations, or work with a provided list of hostnames. 

Then, it will run a port 135 scan to check for alive hosts, and enumerate if there is any local admin access to those hosts. 

Additionally, it will enumerate AD Domain and Enterprise Admins, enumerate users sessions on those hosts where you have local admin access, check if any Domain or Enterprise Admin has a session on any of those hosts, dump SAM from those hosts, dump hashes and tickets from those hosts and save the dumps into your current folder. 

The tool also checks for the presence of Domain or Enterprise Admins tickets or hashes in the dumps.

Run as follows:

`iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/JMove/main/JMove.ps1')`
