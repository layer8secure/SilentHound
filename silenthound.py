import ldap
import socket
import argparse
import colorama
import sys
import ast
import time
from colorama import Fore, Style


parser = argparse.ArgumentParser(description='Quietly enumerate an Active Directory environment.')
parser.add_argument('target', metavar='TARGET', type=str, help='Domain Controller IP')
parser.add_argument('domain', type=str,help="Dot (.) separated Domain name including both contexts e.g. ACME.com / HOME.local / htb.net")
parser.add_argument('-u','--username', type=str, help="LDAP username - not the same as user principal name. E.g. Username: bob.dole might be 'bob dole'")
parser.add_argument('-p','--password', type=str,help="LDAP password - use single quotes 'password'")
parser.add_argument('-o', '--output', type=str, help="Name for output files. Creates output files for hosts, users, domain admins, and descriptions in the current working directory.")
parser.add_argument('-g', '--groups', action='store_true', help="Display Group names with user members.")
parser.add_argument('-n', '--org-unit', action='store_true', help="Display Organizational Units.")
parser.add_argument('-k', '--keywords', action='store_true', help="Search for key words in LDAP objects.")
args = parser.parse_args()

# Global lists

USERNAMES = []
DOMAIN_ADMINS_UPN =[]

# Functions

def banner():
    dashline = "-" * 75
    print(Fore.RED + r"""
   _____ _ _            _   _    _                       _ 
  / ____(_) |          | | | |  | |                     | |
 | (___  _| | ___ _ __ | |_| |__| | ___  _   _ _ __   __| |
  \___ \| | |/ _ \ '_ \| __|  __  |/ _ \| | | | '_ \ / _` |
  ____) | | |  __/ | | | |_| |  | | (_) | |_| | | | | (_| |
 |_____/|_|_|\___|_| |_|\__|_|  |_|\___/ \__,_|_| |_|\__,_|


        """ + Fore.WHITE+ """author: Nick Swink aka c0rnbread

        company: Layer 8 Security <layer8security.com>
        """ + Style.RESET_ALL)
    print(dashline + '\n')


def get_cache():
    try:
        f = open(f".{domain}-{ext}.cache","r")
        cache_str = f.read()
        cache = ast.literal_eval(cache_str)
        print(Fore.YELLOW + f"[*] Located LDAP cache '.{domain}-{ext}.cache'. Delete cache to run updated query ..." + Style.RESET_ALL)
        return cache
        f.close()
    except:
        return None


def create_cache(dump):
    print(Fore.YELLOW + f"[*] No cache found. Creating file to cache LDAP dump '.{domain}-{ext}.cache ...'" + Style.RESET_ALL)
    with open(f".{domain}-{ext}.cache","w") as f:
        f.write(str(dump))
        f.close()


def dump_ldap():
    try:
        # connect
        connect = ldap.initialize(f'ldap://{args.target}')
        # set option
        connect.set_option(ldap.OPT_REFERRALS, 0)
        # bind to server w credentials
        connect.simple_bind_s(args.username, args.password)
        # grab ldap data
        result = connect.search_s(namingcontexts, ldap.SCOPE_SUBTREE)

        if (result[0][1]) == {}:
            print(Fore.RED + "[!] Successful Bind but NO data returned - no permissions??" + Style.RESET_ALL)
            sys.exit()
            return None
        else:
            return result


    except ldap.INVALID_CREDENTIALS:
        print(Fore.RED + f"[!] Error - Invalid Credentials '{args.username}:{args.password}'" + Style.RESET_ALL)
        sys.exit()
    except ldap.INVALID_DN_SYNTAX as err:
        print(Fore.RED + f"[!] Error - Invalid Syntax: {err}" + Style.RESET_ALL)
        sys.exit()
    except Exception as err:
        print(Fore.RED + f"[!] Error - Failure binding to LDAP server\n {(err)}" + Style.RESET_ALL)
        sys.exit()


def resolve_ipv4(hostnames):
    ip_dict_list = []
    for host in hostnames:
        try:
            addrinfo = socket.getaddrinfo(host, 80, family=socket.AF_INET)
            # parse results
            ipv4 = addrinfo[1][4][0]
            # create dictionary of dns and ipv4
            ip_dict_list.append({"Name":host,"Address":ipv4})
        # getaddressinfo(gai) error
        except socket.gaierror as err:
            # print(f"[!] Host isn't alive - Can't get ipv4 ({host})")
            ip_dict_list.append({"Name":host,"Address":"?"})
        except:
            print(Fore.RED + f"[!] Failed getting ipv4 info ({host})" + Style.RESET_ALL)
    return ip_dict_list


def get_user_principal_name(cn):
    user_cn = ""
    for user in cn_upn_dict_list:
        if cn == user['CN']:
            user_cn = user['UserPrincipalName']
        else:
            continue
    return user_cn


def extract_all(dump):
    DOMAIN_ADMINS_CN = []
    COMPUTERS = []
    description_dict_list = []
    ou_list = []
    group_user_dict_list = []
    cn_upn_dict_list = []
    loot_list = []
    key_words = ['Pass','pass','pwd','Pwd','key','userPassword', 'secret']
    default_pwd_words = ["maxPwdAge","minPwdAge","minPwdLength","pwdProperties","pwdHistoryLength","badPwdCount","badPasswordTime","pwdLastSet"]


    for row in dump:
        # users
            try:
                if b'person' in row[1]['objectClass']:
                    user_principal_name_blist = row[1].get('userPrincipalName')
                    if user_principal_name_blist:
                        user_principal_name = user_principal_name_blist[0].decode('UTF-8')
                        USERNAMES.append(user_principal_name)
                    else:
                        user_name_blist = row[1].get('sAMAccountName')
                        user_name = user_name_blist[0].decode('UTF-8')
                        USERNAMES.append(user_name)
            except:
                pass
        # Domain admins
            try:
                if b'group' in row[1]['objectClass'] and b'Domain Admins' in row[1]['cn']:
                    member_blist = row[1]['member']
                    DOMAIN_ADMINS_CN = [member.decode('UTF-8') for member in member_blist]
            except:
                pass

        # Computers
            try:
                if b'computer' in row[1]['objectClass']:
                    # parse short cn
                    cn_blist = (row[1]["cn"])
                    cn = cn_blist[0].decode('UTF-8')
                    if cn == 'Computers':
                        pass
                    else:
                        COMPUTERS.append(cn)
            except:
                pass
            
        # Descriptions
            try:
                if b'person' in row[1]['objectClass']:
                    upn_blist = row[1]['userPrincipalName']
                    d_blist = row[1]['description']
                    upn = upn_blist[0].decode('UTF-8')
                    d = d_blist[0].decode('UTF-8')
                    description_dict_list.append({"UserPrincipalName":upn, "description":d})
            except:
                pass

        # Map cn --> upn
            try:
                if b'person' in row[1]['objectClass']:
                    # dictionary matches CN list to UserPrincipalName for use elsewhere
                    upn_blist = (row[1]["userPrincipalName"])
                    upn = upn_blist[0].decode('UTF-8')
                    cn_upn_dict = {"CN":row[0],"UserPrincipalName":upn}
                    cn_upn_dict_list.append(cn_upn_dict)
            except:
                pass

        # Groups
            if args.groups:
                try:
                    if b'group' in row[1]['objectClass']:
                        member_blist = row[1]['member']
                        member_list = [i.decode('UTF-8') for i in member_blist]
                        group_user_dict_list.append({'Group':row[0], 'Members':member_list})
                except:
                    pass

        # OUs
            if args.org_unit:
                try:
                    if b'organizationalUnit' in row[1].get('objectClass'):
                        ou_list.append(row[0])
                except:
                    pass

        # Search key phrases
            if args.keywords:
                try:
                    for key in row[1]:
                        # search keys
                        if any(word in key for word in key_words):
                            if key not in default_pwd_words:
                                loot_list.append(f"{key}={(row[1].get(key))[0].decode('UTF-8')}")   # pwd=[b'p@$$w0rd']
                        # search key values
                        for item in row[1].get(key):
                            try:
                                item = item.decode('UTF-8')
                                if any(word in item for word in key_words):
                                    loot_list.append(item)
                            except:
                                continue
                except:
                    continue


    return COMPUTERS, description_dict_list, cn_upn_dict_list, DOMAIN_ADMINS_CN, group_user_dict_list, ou_list, loot_list


if __name__ == "__main__":
    # parse domain.ext
    if '.' not in args.domain:
        print("[!] Domain must contain DOT (.); e.g. 'ACME.com'")
        sys.exit()
    else:
        domain = args.domain.split('.')[0]
        ext = args.domain.split('.')[1]
        namingcontexts = f"dc={domain},dc={ext}"

    print()
    banner()

    # Check for cache
    cache = get_cache()

    # DUMP LDAP FIRST
    if not cache:
        dump = dump_ldap()
        create_cache(dump)
    else:
        dump = cache
    time.sleep(1.5)


    COMPUTERS, description_dict_list, cn_upn_dict_list, DOMAIN_ADMINS_CN, group_user_dict_list, ou_list, loot_list = extract_all(dump)
    
    # get exact casing of domain from upn in ldap
    domain = cn_upn_dict_list[0]['UserPrincipalName'].split('@')[1].split('.')[0]

    # Resolve DNS names to IPv4
    ip_dict_list = resolve_ipv4(COMPUTERS)


    # Print Hosts
    print(Fore.GREEN + "[+] Hosts" + Style.RESET_ALL)
    for i in range(len(ip_dict_list)):
        print(f"{ip_dict_list[i]['Name']} - {ip_dict_list[i]['Address']}")
    print('\n')


    # Print Domain Admins
    print(Fore.GREEN + "[+] Domain Admins" + Style.RESET_ALL)
    for item in DOMAIN_ADMINS_CN:
        user_cn = get_user_principal_name(item)
        if user_cn:
            print(user_cn)
            DOMAIN_ADMINS_UPN.append(user_cn)
        else:
            print(item)
    print('\n')


    # Print Users
    print(Fore.GREEN + "[+] Domain Users" + Style.RESET_ALL)
    for i in range(len(USERNAMES)):
        print(USERNAMES[i])

    print('\n')


    # Print Descriptions
    print(Fore.GREEN + "[+] Descriptions" + Style.RESET_ALL)
    for d in description_dict_list:
        print(f"{d['UserPrincipalName']} - {d['description']}")
    print('\n')


    # Print Groups
    special_words = ['Remote','Admin','Service']
    if args.groups:
            print(Fore.GREEN + "[+] Group Memberships Found" + Style.RESET_ALL)
            for i in group_user_dict_list:
                if any(word in i['Group'] for word in special_words):
                    print(Fore.RED + i['Group'] + Style.RESET_ALL)
                else:
                    print(Fore.BLUE + i['Group'] + Style.RESET_ALL)

                # print members of group by upn name
                for m in i['Members']:
                    user_cn = get_user_principal_name(m)
                    if user_cn:
                        print(user_cn)
                    else:
                        print(m)
                print('\n')


    # Print OUs
    if args.org_unit:
        print(Fore.GREEN + "[+] Organizational Units Found" + Style.RESET_ALL)
        for ou in ou_list:
            print(ou)
        print('\n')


    # Print Passwords
    if args.keywords:
        print(Fore.GREEN + "[+] Key Strings" + Style.RESET_ALL)
        for l in loot_list:
            print(f"{l}")
        print('\n')


# OUTFILES (optional)
    if args.output:

        with open(f"{args.output}-users.txt", "w") as f:
            for line in USERNAMES:
                f.write(line)
                f.write('\n')
            f.close()

        with open(f"{args.output}-domain_admins.txt", "w") as f:
            for line in DOMAIN_ADMINS_UPN:
                f.write(line)
                f.write('\n')
            f.close()

        with open(f"{args.output}-hosts.txt","w") as f:
            for line in range(len(ip_dict_list)):
                f.write(f"{ip_dict_list[line]['Name']} {ip_dict_list[line]['Address']}")
                f.write('\n')
            f.close()

        with open(f"{args.output}-descriptions.txt", "w") as f:
            for line in description_dict_list:
                f.write(f"{line['UserPrincipalName']} {line['description']}")
                f.write('\n')
            f.close()

        if args.groups:
            with open(f"{args.output}-groups.txt", "w") as f:
                for i in group_user_dict_list:
                    f.write('\n')
                    f.write(f"- {i['Group']}")
                    # print members of group by upn name
                    for m in i['Members']:
                        user_cn = get_user_principal_name(m)
                        if user_cn:
                            f.write('\n')
                            f.write(user_cn)
                        else:
                            f.write('\n')
                            f.write(m)
                    f.write('\n')
                f.close()

        if args.org_unit:
            with open(f"{args.output}-org.txt", "w") as f:
                for ou in ou_list:
                    f.write('\n')
                    f.write(ou)
                f.close()

        if args.keywords:
            with open(f"{args.output}-keywords.txt","w") as f:
                for l in loot_list:
                    f.write(l)
                    f.write('\n')
                f.close()

