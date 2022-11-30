![Layer-8-Logo-Wide](https://user-images.githubusercontent.com/8293038/96061566-93d8af00-0e61-11eb-8b84-3fd207290be2.png)

# SilentHound
Quietly enumerate an Active Directory Domain via LDAP parsing users, admins, groups, etc. Created by [Nick Swink](https://github.com/nickswink) from [Layer 8 Security](https://layer8security.com).

### Installation

#### Using pipenv (recommended method)
    python3 -m pip install --user pipenv
    git clone https://github.com/layer8secure/SilentHound.git
    cd silenthound
    pipenv install

> :information_source: This will create an isolated virtual environment with dependencies needed for the project. To use the project you can either open a 
shell in the virtualenv with `pipenv shell` or run commands directly with `pipenv run`.

#### From requirements.txt (legacy)
> :warning: This method is not recommended because python-ldap can cause many dependency errors.

Install dependencies with `pip`:

    python3 -m pip install -r requirements.txt
    python3 silenthound.py -h

### Usage
    $ pipenv run python silenthound.py -h
    usage: silenthound.py [-h] [-u USERNAME] [-p PASSWORD] [--hashes HASHES] [-o OUTPUT] [-g] [-n] [-k] [--kerberoast] [--ssl] TARGET domain

    Quietly enumerate an Active Directory environment.

    positional arguments:
      TARGET                Domain Controller IP
      domain                Dot (.) separated Domain name including both contexts e.g. ACME.com | HOME.local | htb.net

    optional arguments:
      -h, --help            show this help message and exit
      -u USERNAME, --username USERNAME
                            Supports SIMPLE & NTLM BIND. SIMPLE BIND use username e.g. bobdole | NTLM BIND use domain\\user e.g. HOME.local\\bobdole
      -p PASSWORD, --password PASSWORD
                            LDAP or Active Directory password
      --hashes HASHES       Uses NTLM BIND to authenticate with NT:LM hashes
      -o OUTPUT, --output OUTPUT
                            Name for output files. Creates output files for hosts, users, domain admins, and descriptions in the current working directory.
      -g, --groups          Display Group names with user members.
      -n, --org-unit        Display Organizational Units.
      -k, --keywords        Search for a list of key words in LDAP objects.
      --kerberoast          Identify kerberoastable user accounts by their SPNs.
      --ssl                 Use a secure LDAP server on default 636 port.  


### Example
    $ pipenv run python silenthound.py -u 'svc_tgs' -p 'P@$$w0rd123' 10.10.10.100 active.htb -g -n -k --kerberoast


     _____ _ _            _   _    _                       _ 
    / ____(_) |          | | | |  | |                     | |
    | (___  _| | ___ _ __ | |_| |__| | ___  _   _ _ __   __| |
    \___ \| | |/ _ \ '_ \| __|  __  |/ _ \| | | | '_ \ / _` |
    ____) | | |  __/ | | | |_| |  | | (_) | |_| | | | | (_| |
    |_____/|_|_|\___|_| |_|\__|_|  |_|\___/ \__,_|_| |_|\__,_|


      author: Nick Swink aka c0rnbread

      company: Layer 8 Security <layer8security.com>
      
    ---------------------------------------------------------------------------

    [-] Connecting with SIMPLE AUTH to LDAP server 10.10.10.100...
    [*] Writing cached data to .active-htb.pickle...
    [+] Hosts [1]
    DC - 10.10.10.100


    [+] Domain Admins [1]
    CN=Administrator,CN=Users,DC=active,DC=htb


    [+] Domain Users [4]
    krbtgt
    Guest
    Administrator
    SVC_TGS@active.htb


    [+] Descriptions [0]


    [+] Group Memberships Found [11]
    CN=Denied RODC Password Replication Group,CN=Users,DC=active,DC=htb
    CN=Read-only Domain Controllers,CN=Users,DC=active,DC=htb
    CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb
    CN=Domain Admins,CN=Users,DC=active,DC=htb
    CN=Cert Publishers,CN=Users,DC=active,DC=htb
    CN=Enterprise Admins,CN=Users,DC=active,DC=htb
    CN=Schema Admins,CN=Users,DC=active,DC=htb
    CN=Domain Controllers,CN=Users,DC=active,DC=htb
    CN=krbtgt,CN=Users,DC=active,DC=htb


    CN=Windows Authorization Access Group,CN=Builtin,DC=active,DC=htb
    CN=S-1-5-9,CN=ForeignSecurityPrincipals,DC=active,DC=htb


    CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=active,DC=htb
    CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=active,DC=htb


    CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb
    CN=Administrator,CN=Users,DC=active,DC=htb


    CN=Domain Admins,CN=Users,DC=active,DC=htb
    CN=Administrator,CN=Users,DC=active,DC=htb


    CN=Enterprise Admins,CN=Users,DC=active,DC=htb
    CN=Administrator,CN=Users,DC=active,DC=htb


    CN=Schema Admins,CN=Users,DC=active,DC=htb
    CN=Administrator,CN=Users,DC=active,DC=htb


    CN=IIS_IUSRS,CN=Builtin,DC=active,DC=htb
    CN=S-1-5-17,CN=ForeignSecurityPrincipals,DC=active,DC=htb


    CN=Guests,CN=Builtin,DC=active,DC=htb
    CN=Domain Guests,CN=Users,DC=active,DC=htb
    CN=Guest,CN=Users,DC=active,DC=htb


    CN=Users,CN=Builtin,DC=active,DC=htb
    CN=Domain Users,CN=Users,DC=active,DC=htb
    CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=active,DC=htb
    CN=S-1-5-4,CN=ForeignSecurityPrincipals,DC=active,DC=htb


    CN=Administrators,CN=Builtin,DC=active,DC=htb
    CN=Domain Admins,CN=Users,DC=active,DC=htb
    CN=Enterprise Admins,CN=Users,DC=active,DC=htb
    CN=Administrator,CN=Users,DC=active,DC=htb


    [+] Organizational Units Found [1]
    OU=Domain Controllers,DC=active,DC=htb


    [+] Key Strings [18]
    CN=Denied RODC Password Replication Group,CN=Users,DC=active,DC=htb
    Denied RODC Password Replication Group
    Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
    CN=Denied RODC Password Replication Group,CN=Users,DC=active,DC=htb
    Denied RODC Password Replication Group
    Denied RODC Password Replication Group
    Allowed RODC Password Replication Group
    Members in this group can have their passwords replicated to all read-only domain controllers in the domain
    CN=Allowed RODC Password Replication Group,CN=Users,DC=active,DC=htb
    Allowed RODC Password Replication Group
   


    [+] Kerberoastable Users [1]
    ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet  LastLogon  
    --------------------  -------------  --------------------------------------------------------  ---------------  ----------
    active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18       2022-11-30 




### About
A lightweight tool to quickly and quietly enumerate an Active Directory environment. The goal of this tool is to get a Lay of the Land whilst making as little noise on the network as possible. The tool will make one LDAP query that is used for parsing, and create a cache file to prevent further queries/noise on the network. If no credentials are passed it will attempt anonymous BIND. 

Using the `-o` flag will result in output files for each section normally in stdout. The files created using all flags will be:

    -rw-r--r--  1 kali  kali   122 Jun 30 11:37 BASENAME-descriptions.txt
    -rw-r--r--  1 kali  kali    60 Jun 30 11:37 BASENAME-domain_admins.txt
    -rw-r--r--  1 kali  kali  2620 Jun 30 11:37 BASENAME-groups.txt
    -rw-r--r--  1 kali  kali    89 Jun 30 11:37 BASENAME-hosts.txt
    -rw-r--r--  1 kali  kali  1940 Jun 30 11:37 BASENAME-keywords.txt
    -rw-r--r--  1 kali  kali    66 Jun 30 11:37 BASENAME-org.txt
    -rw-r--r--  1 kali  kali   529 Jun 30 11:37 BASENAME-users.txt


### Author
- [Nick Swink](https://github.com/nickswink) - Security Consultant at [Layer 8 Security](https://layer8security.com)

### Roadmap / Updates
:white_check_mark: support ntlm hash auth
- match strings with regex in --keyword
- convert cache into bloodhound compatible file to reduce traffic


For additional feature requests please submit an [issue](https://github.com/layer8secure/SilentHound/issues/new) and add the `enhancement` tag.



