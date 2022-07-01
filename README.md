![Layer-8-Logo-Wide](https://user-images.githubusercontent.com/8293038/96061566-93d8af00-0e61-11eb-8b84-3fd207290be2.png)

# SilentHound
Quietly enumerate an Active Directory Domain via LDAP parsing users, admins, groups, etc. Created by [Nick Swink](https://github.com/nickswink) from [Layer 8 Security](https://layer8security.com).

### Installation

#### Using pipenv (recommended method)
    sudo python3 -m pip install --user pipenv
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
    usage: silenthound.py [-h] [-u USERNAME] [-p PASSWORD] [-o OUTPUT] [-g] [-n] [-k] TARGET domain

    Quietly enumerate an Active Directory environment.

    positional arguments:
      TARGET                Domain Controller IP
      domain                Dot (.) separated Domain name including both contexts e.g. ACME.com / HOME.local / htb.net

    optional arguments:
      -h, --help            show this help message and exit
      -u USERNAME, --username USERNAME
                            LDAP username - not the same as user principal name. E.g. Username: bob.dole might be 'bob
                            dole'
      -p PASSWORD, --password PASSWORD
                            LDAP password - use single quotes 'password'
      -o OUTPUT, --output OUTPUT
                            Name for output files. Creates output files for hosts, users, domain admins, and descriptions
                            in the current working directory.
      -g, --groups          Display Group names with user members.
      -n, --org-unit        Display Organizational Units.
      -k, --keywords        Search for key words in LDAP objects.


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

### Roadmap
- Parse users belonging to specific OUs
- Refine output
- Continuously cleanup code
- Move towards OOP

For additional feature requests please submit an [issue](https://github.com/layer8secure/SilentHound/issues/new) and add the `enhancement` tag.


