#!/usr/bin/python3

import time, sys, socket
import argparse
import pickle
import ast
from colorama import Fore, Style
from os.path import exists
from ldap3 import Server, Connection, AUTO_BIND_NO_TLS, SUBTREE, ALL_ATTRIBUTES, SAFE_SYNC
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPInvalidDNSyntaxResult, LDAPSocketOpenError
from alive_progress import alive_bar

# Const
NTLM = "NTLM"
SIMPLE = "SIMPLE"
ANONYMOUS = "ANONYMOUS"

# Global Funcs

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


def get_user_principal_name(cn, cn_upn_dict_list):
	user_cn = None
	for user in cn_upn_dict_list:
		if cn == user['CN']:
			user_cn = user['UserPrincipalName']
		else:
			continue
	return user_cn


# Borrowed from impacket-GetUserSPNs.py
# Author:
#   Alberto Solino (@agsolino)
def getUnixTime(t):
		t -= 116444736000000000
		t /= 10000000
		return t


# Borrowed from impacket-GetUserSPNs.py
# Author:
#   Alberto Solino (@agsolino)
def printTable(items, header):
	colLen = []
	for i, col in enumerate(header):
		rowMaxLen = max([len(row[i]) for row in items])
		colLen.append(max(rowMaxLen, len(col)))

	outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])

	# Print header
	print(outputFormat.format(*header))
	print('  '.join(['-' * itemLen for itemLen in colLen]))

	# And now the rows
	for row in items:
		print(outputFormat.format(*row))


# caching class

class Pickler():

	def __init__(self, filename):
		self.__filename = filename

	def save_object(self, data):
		try:
			print(Fore.YELLOW + f"[*] Writing cached data to .{domain}-{ext}.pickle..." + Style.RESET_ALL)
			with open(self.__filename, "wb") as f:
				pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
		except Exception as err:
			print(Fore.RED + f"[!] Error during pickling object: {err}" + Style.RESET_ALL)

	def load_object(self):
		if not exists(f".{domain}-{ext}.pickle"):
			return None
		try:
			with open(self.__filename, "rb") as f:
				print(Fore.YELLOW + f"[*] Located LDAP cache '.{domain}-{ext}.pickle'. Delete cache to run updated query..." + Style.RESET_ALL)
				return pickle.load(f)
		except Exception as err:
			print(Fore.RED + f"[!] Error during unpickling object: {err}" + Style.RESET_ALL)
			return None


# dump and processor

class Hound:

	def __init__(self, namingcontexts):
		self.__namingcontexts = namingcontexts
		self.__usernames = []
		self.__domain_admins_upn =[]
		self.__domain_admins_cn = []
		self.__computers = []
		self.__ip_dict_list = []
		self.__description_dict_list = []
		self.__ou_list = []
		self.__group_user_dict_list = []
		self.__cn_upn_dict_list = []
		self.__loot_list = []
		self.__kerberostable_users = []
		self.__key_words = ['Pass','pass','pwd','Pwd','key','userPassword', 'secret']
		self.__default_pwd_words = ["maxPwdAge","minPwdAge","minPwdLength","pwdProperties","pwdHistoryLength","badPwdCount","badPasswordTime","pwdLastSet"]
		self.__special_words = ['Remote','Admin','Service']


	def dump_ldap(self):

		try:			

			s = Server(args.target, use_ssl=args.ssl, get_info='ALL')

			password = args.password
			# logic for BIND method
			if args.username == '' and args.password == '':
				method = ANONYMOUS
			elif not '\\' in args.username:
				method = SIMPLE
			else:
				method = NTLM
				password = args.hashes if args.hashes else args.password

			if args.hashes and method == SIMPLE:
				print(Fore.RED + f"[!] Cannot use Pass the Hash with SIMPLE AUTH. Exiting..." + Style.RESET_ALL)
				sys.exit()	

			server = "LDAPS" if args.ssl else "LDAP"
			print(Fore.BLUE + f"[-] Connecting with {method} AUTH to {server} server {args.target}..." + Style.RESET_ALL)
			
			connect = Connection(s, user=args.username, password=password, client_strategy=SAFE_SYNC, auto_bind=True, authentication=method)

			search_flt = "(objectClass=*)" # specific search filters
			results = connect.extend.standard.paged_search(search_base=self.__namingcontexts, search_filter=search_flt, search_scope=SUBTREE, attributes=ALL_ATTRIBUTES, get_operational_attributes=True)

			total_results = []

			for item in results:
				total_results.append(item)

			return total_results

				
		except LDAPInvalidCredentialsResult:
			print(Fore.RED + f"[!] Error - Invalid Credentials '{args.username}:{args.password}'" + Style.RESET_ALL)
			sys.exit()
		except LDAPInvalidDNSyntaxResult as err:
			print(Fore.RED + f"[!] Error - Invalid Syntax: {err}" + Style.RESET_ALL)
			sys.exit()
		except LDAPSocketOpenError as err:
			print(Fore.RED + f"[!] Error - Couldn't reach LDAP server" + Style.RESET_ALL)
			sys.exit()
		except Exception as err:
			print(Fore.RED + f"[!] Error - Failure binding to LDAP server\n {(err)}" + Style.RESET_ALL)
			sys.exit()


	def resolve_ipv4(self, timeout):
		start_time = time.time()
		#print(self.__computers)
		with alive_bar(len(self.__computers), dual_line=True, title=Fore.YELLOW + "[*] Resolving hostnames" + Style.RESET_ALL) as bar:
			for host in self.__computers:
				try:
					addrinfo = socket.getaddrinfo(host, 80, family=socket.AF_INET)
					# parse results
					ipv4 = addrinfo[1][4][0]
					# create dictionary of dns and ipv4
					self.__ip_dict_list.append({"Name":host,"Address":ipv4})
				except KeyboardInterrupt:
				    # quit
				    sys.exit()
				# getaddressinfo(gai) error
				except socket.gaierror as err:
					# print(f"[!] Host isn't alive - Can't get ipv4 ({host})")
					self.__ip_dict_list.append({"Name":host,"Address":""})
				except:
					self.__ip_dict_list.append({"Name":host,"Address":""})
					print(Fore.RED + f"[!] Failed getting ipv4 info ({host})" + Style.RESET_ALL)
			   
				# Check if its going to take too long
				if (time.time() - start_time) > timeout:
					print(Fore.YELLOW + f"[*] Reverse DNS taking too long, skipping..." + Style.RESET_ALL)
					current_index = self.__computers.index(host)
					for host_left in self.__computers[current_index:]:
							self.__ip_dict_list.append({"Name":host_left,"Address":""})
					break

				bar()

	def extract_all(self,dump):

		def create_cn_upn_dict_list(dump):
			# Map cn --> upn
			for row in dump:
				try:
					if b'person' in row['raw_attributes']['objectClass']:
						# dictionary matches CN list to UserPrincipalName for use elsewhere
						upn_blist = (row['raw_attributes']["userPrincipalName"])
						upn = upn_blist[0].decode('UTF-8')
						cn_upn_dict = {"CN":row['dn'],"UserPrincipalName":upn}
						self.__cn_upn_dict_list.append(cn_upn_dict)
				except:
					pass

		# Get a dictionary of common names to userPrincipalNames first
		create_cn_upn_dict_list(dump)

		for row in dump:
			# Extract all users
			try:
				if b'person' in row['raw_attributes']['objectClass'] and b'computer' not in row['raw_attributes']['objectClass']:
					user_principal_name_blist = row['raw_attributes'].get('userPrincipalName')
					if user_principal_name_blist:
						user_principal_name = user_principal_name_blist[0].decode('UTF-8')
						self.__usernames.append(user_principal_name)
					else:
						user_name_blist = row['raw_attributes'].get('sAMAccountName')
						user_name = user_name_blist[0].decode('UTF-8')
						self.__usernames.append(user_name)
			except:
				pass

			# Extract all Domain admins
			try:
				if b'group' in row['raw_attributes']['objectClass'] and b'Domain Admins' in row['raw_attributes']['cn']:
					member_blist = row['raw_attributes']['member']
					self.__domain_admins_cn = [member.decode('UTF-8') for member in member_blist]
					for user_cn in self.__domain_admins_cn:
						user_upn = get_user_principal_name(user_cn, self.__cn_upn_dict_list)
						if user_upn:
							self.__domain_admins_upn.append(user_upn)
						else:
							self.__domain_admins_upn.append(user_cn)
			except:
				pass

			# Extract all hosts
			try:
				if b'computer' in row['raw_attributes']['objectClass']:
					# parse short cn
					cn_blist = (row['raw_attributes']["cn"])
					cn = cn_blist[0].decode('UTF-8')
					if cn in self.__computers:
						pass
					else:
						self.__computers.append(cn)
			except:
				pass


			# Extract all Descriptions
			try:
				if b'person' in row['raw_attributes']['objectClass']:
					upn_blist = row['raw_attributes']['userPrincipalName']
					d_blist = row['raw_attributes']['description']
					upn = upn_blist[0].decode('UTF-8')
					d = d_blist[0].decode('UTF-8')
					self.__description_dict_list.append({"UserPrincipalName":upn, "description":d})
			except:
				pass

			# Extract all Groups
			if args.groups:
				try:
					if b'group' in row['raw_attributes']['objectClass']:
						member_blist = row['raw_attributes']['member']
						member_list = [i.decode('UTF-8') for i in member_blist]
						self.__group_user_dict_list.append({'Group':row['dn'], 'Members':member_list})
				except:
					pass
			# Extract all OUs
			if args.org_unit:
				try:
					if b'organizationalUnit' in row['raw_attributes'].get('objectClass'):
						self.__ou_list.append(row['dn'])
				except:
					pass

			# Extract all key phrases
			if args.keywords:
				try:
					for key in row['raw_attributes']:
						object_name = user_principal_name if user_principal_name else ""
						# search key names
						if any(word in key for word in self.__key_words):
							if key not in self.__default_pwd_words:
								self.__loot_list.append(f"({object_name}) {key}={(row['raw_attributes'].get(key))[0].decode('UTF-8')}")   # e.g. pwd=[b'p@$$w0rd'] -> pwd='p@$$w0rd'
						# search key values
						for item in row['raw_attributes'].get(key):
							try:
								item = item.decode('UTF-8')
								if any(word in item for word in self.__key_words):
									self.__loot_list.append(item)
							except:
								continue

				except:
					continue


# Function influenced by GetUserSPNs.py but without using impacket library.
# Author:
#   Alberto Solino (@agsolino)

	def kerberoastable(self, total_results):
		
		if args.kerberoast:
			
			import datetime
			
			kerberoastable = []

			# Lets look for objects with SPNs
			for obj in total_results:
				try:
					# userAccountControl = obj[1]['userAccountControl'][0]
					servicePrincipalName = obj['raw_attributes']['servicePrincipalName']
					# UAC values - 
					# https://jackstromberg.com/2013/01/useraccountcontrol-attributeflag-values/

					# good_UACs = [b'512', b'66176', b'65536', b'66048', b'640']
					
					if b'computer' not in obj['raw_attributes']['objectClass'] and servicePrincipalName:
						kerberoastable.append(obj)

				except Exception as e:
					# print("error as %s" % e)
					continue

			# Lets get the desired attributes in a list
			for obj in kerberoastable:
				mustCommit = False
				sAMAccountName = ''
				memberOf = ''
				SPNs = []
				pwdLastSet = ''
				userAccountControl = 0
				lastLogon = 'N/A'

				try:
					for attribute in obj['raw_attributes']:
						if attribute == 'sAMAccountName':
							sAMAccountName = str(obj['raw_attributes'].get('sAMAccountName')[0].decode('UTF-8'))
							mustCommit = True
						elif attribute == 'userAccountControl':
							userAccountControl = str(obj['raw_attributes'].get('userAccountControl')[0].decode('UTF-8'))
						elif attribute == 'memberOf':
							memberOf = str(obj['raw_attributes'].get('memberOf')[0].decode('UTF-8'))
						elif attribute == 'pwdLastSet':
							if obj['raw_attributes'].get(attribute)[0].decode('UTF-8') == '0':
								pwdLastSet = 'never'
							else:
								pwdLastSet = str(datetime.date.fromtimestamp(getUnixTime(int(str(obj['raw_attributes'].get(attribute)[0].decode('UTF-8'))))))
						elif attribute == 'lastLogon':
							if obj['raw_attributes'].get(attribute)[0].decode('UTF-8') == '0':
								lastLogon = 'never'
							else:
								lastLogon = str(datetime.date.fromtimestamp(getUnixTime(int(str(obj['raw_attributes'].get(attribute)[0].decode('UTF-8'))))))
						elif attribute == 'servicePrincipalName':
							for spn in obj['raw_attributes'].get(attribute):
								spn = spn.decode('UTF-8')
								SPNs.append(str(spn))
					
					# Make sure the account isn't disabled
					if mustCommit is True:
						disabled_UACs = [514, 546, 66050, 66082, 262658, 262690, 328194, 328226]
						if int(userAccountControl) in disabled_UACs:
							#print('Bypassing disabled account %s ' % sAMAccountName)
							pass
						else:
							for spn in SPNs:
								self.__kerberostable_users.append([spn, sAMAccountName, memberOf, pwdLastSet, lastLogon])

				except Exception as e:
					print('Skipping item, cannot process due to error %s' % str(e))
					pass


	def print(self):
		# Print Hosts
		print(Fore.GREEN + f"[+] Hosts [{len(self.__ip_dict_list)}]" + Style.RESET_ALL)
		for i in range(len(self.__ip_dict_list)):
			print(f"{self.__ip_dict_list[i]['Name']} {self.__ip_dict_list[i]['Address']}")
		print('\n')

		# Print Domain Admins
		print(Fore.GREEN + f"[+] Domain Admins [{len(self.__domain_admins_upn)}]" + Style.RESET_ALL)
		for user_upn in self.__domain_admins_upn:
			print(user_upn)
		print('\n')

		# Print Users
		print(Fore.GREEN + f"[+] Domain Users [{len(self.__usernames)}]" + Style.RESET_ALL)
		for i in range(len(self.__usernames)):
			print(self.__usernames[i])

		print('\n')

		# Print Descriptions
		print(Fore.GREEN + f"[+] Descriptions [{len(self.__description_dict_list)}]" + Style.RESET_ALL)
		for d in self.__description_dict_list:
			print(f"{d['UserPrincipalName']} - {d['description']}")
		print('\n')

		# Print Groups
		if args.groups:
			print(Fore.GREEN + f"[+] Group Memberships Found [{len(self.__group_user_dict_list)}]" + Style.RESET_ALL)
			for group in self.__group_user_dict_list:
				if any(word in group['Group'] for word in self.__special_words):
					print(Fore.RED + group['Group'] + Style.RESET_ALL)
				else:
					print(Fore.BLUE + group['Group'] + Style.RESET_ALL)

				# print members of group by upn name
				for cn in group['Members']:
					user_cn = get_user_principal_name(cn, self.__cn_upn_dict_list)
					if user_cn:
						print(user_cn)
					else:
						print(cn)
				print('\n') 

		# Print OUs
		if args.org_unit:
			print(Fore.GREEN + f"[+] Organizational Units Found [{len(self.__ou_list)}]" + Style.RESET_ALL)
			for ou in self.__ou_list:
				print(ou)
			print('\n')


		# Print Passwords
		if args.keywords:
			print(Fore.GREEN + f"[+] Key Strings [{len(self.__loot_list)}]" + Style.RESET_ALL)
			for l in self.__loot_list:
				print(f"{l}")
			print('\n')

		# Print kerberoastable accounts in impacket style table
		if args.kerberoast:
			print(Fore.GREEN + f"[+] Kerberoastable Users [{len(self.__kerberostable_users)}]" + Style.RESET_ALL)
			if len(self.__kerberostable_users) > 0:
				printTable(self.__kerberostable_users, header=["ServicePrincipalName", "Name", "MemberOf", "PasswordLastSet", "LastLogon"])
				print('\n')

	def outfiles(self):
		# OUTFILES (optional)
		if args.output:

			with open(f"{args.output}-users.txt", "w") as f:
				for line in self.__usernames:
					f.write(line)
					f.write('\n')

			with open(f"{args.output}-domain_admins.txt", "w") as f:
				for line in self.__domain_admins_upn:
					f.write(line)
					f.write('\n')

			with open(f"{args.output}-hosts.txt","w") as f:
				for line in range(len(self.__ip_dict_list)):
					f.write(f"{self.__ip_dict_list[line]['Name']} {self.__ip_dict_list[line]['Address']}")
					f.write('\n')

			with open(f"{args.output}-descriptions.txt", "w") as f:
				for line in self.__description_dict_list:
					f.write(f"{line['UserPrincipalName']} {line['description']}")
					f.write('\n')

			if args.groups:
				with open(f"{args.output}-groups.txt", "w") as f:
					for i in self.__group_user_dict_list:
						f.write('\n')
						f.write(f"- {i['Group']}")
						# print members of group by upn name
						for cn in i['Members']:
							user_cn = get_user_principal_name(cn, self.__cn_upn_dict_list)
							if user_cn:
								f.write('\n')
								f.write(user_cn)
							else:
								f.write('\n')
								f.write(cn)
						f.write('\n')

			if args.org_unit:
				with open(f"{args.output}-org.txt", "w") as f:
					for ou in self.__ou_list:
						f.write('\n')
						f.write(ou)

			if args.keywords:
				with open(f"{args.output}-keywords.txt","w") as f:
					for l in self.__loot_list:
						f.write(l)
						f.write('\n')



if __name__ == "__main__":

	# Set args

	parser = argparse.ArgumentParser(description='Quietly enumerate an Active Directory environment.')
	parser.add_argument('target', metavar='TARGET', type=str, help='Domain Controller IP')
	parser.add_argument('domain', type=str,help="Dot (.) separated Domain name including both contexts e.g. ACME.com | HOME.local | htb.net")
	parser.add_argument('-u','--username', default='', type=str, help="Supports SIMPLE & NTLM BIND. SIMPLE BIND use username e.g. bobdole |  NTLM BIND use domain\\\\user e.g. HOME.local\\\\bobdole")
	parser.add_argument('-p','--password', default='', type=str,help="LDAP or Active Directory password")
	parser.add_argument('--hashes',type=str, help="Uses NTLM BIND to authenticate with NT:LM hashes")
	parser.add_argument('-o', '--output', type=str, help="Name for output files. Creates output files for hosts, users, domain admins, and descriptions in the current working directory.")
	parser.add_argument('-g', '--groups', action='store_true', help="Display Group names with user members.")
	parser.add_argument('-n', '--org-unit', action='store_true', help="Display Organizational Units.")
	parser.add_argument('-k', '--keywords', action='store_true', help="Search for a list of key words in LDAP objects.")
	parser.add_argument('--kerberoast', action='store_true', help="Identify kerberoastable user accounts by their SPNs.")
	parser.add_argument('--ssl', action='store_true', help="Use a secure LDAP server on default 636 port.")
	parser.add_argument('--dns-timeout', type=int, default='999999999', help="Useful if resolving hostnames is taking too long. (seconds) e.g. --dns-timeout 90")
	args = parser.parse_args()


	# parse domain.ext
	if '.' not in args.domain:
		print("[!] Domain must contain DOT (.); e.g. 'ACME.com'")
		sys.exit()
	else:
		domain = args.domain.split('.')[0]
		ext = args.domain.split('.')[1]

		l = args.domain.split('.')
		namingcontexts = ""
		for word in l:
			if word == l[-1]:
				namingcontexts += f"DC={word}"
			else:
				namingcontexts += f"DC={word},"


	print()
	banner()

# Hound parser object
	h1 = Hound(namingcontexts)

# Caching functions
	p1 = Pickler(f".{domain}-{ext}.pickle")		# takes filename
	
	# Check for cache
	cache = p1.load_object()
	
	# Use cache otherwise new ldap dump
	if not cache:
		dump = h1.dump_ldap()
		p1.save_object(dump)
	else:
		dump = cache
	time.sleep(1.5)

# Extract all stuffs
	h1.extract_all(dump)

# Resolve DNS names to IPv4
	h1.resolve_ipv4(args.dns_timeout)

# Check for kerberoastable accounts
	h1.kerberoastable(dump)

# Print stuff
	h1.print()

# Output to files
	h1.outfiles()



