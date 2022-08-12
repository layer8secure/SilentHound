#!/usr/bin/python3

import time, sys, socket
import argparse
import ldap
import ast
from colorama import Fore, Style

# Set args

parser = argparse.ArgumentParser(description='Quietly enumerate an Active Directory environment.')
parser.add_argument('target', metavar='TARGET', type=str, help='Domain Controller IP')
parser.add_argument('domain', type=str,help="Dot (.) separated Domain name including both contexts e.g. ACME.com / HOME.local / htb.net")
parser.add_argument('-u','--username', type=str, help="Use fully qualified domain name (bdole@home.local) or LDAP username ('bob dole')")
parser.add_argument('-p','--password', type=str,help="Active Directory password'")
parser.add_argument('-o', '--output', type=str, help="Name for output files. Creates output files for hosts, users, domain admins, and descriptions in the current working directory.")
parser.add_argument('-g', '--groups', action='store_true', help="Display Group names with user members.")
parser.add_argument('-n', '--org-unit', action='store_true', help="Display Organizational Units.")
parser.add_argument('-k', '--keywords', action='store_true', help="Search for a list of key words in LDAP objects.")
args = parser.parse_args()


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


def get_cache():
	try:
		f = open(f".{domain}-{ext}.cache","r")
		cache_str = f.read()
		cache = ast.literal_eval(cache_str)
		print(Fore.YELLOW + f"[*] Located LDAP cache '.{domain}-{ext}.cache'. Delete cache to run updated query ..." + Style.RESET_ALL)
		f.close()
		return cache
	except:
		return None


def create_cache(dump):
	print(Fore.YELLOW + f"[*] Caching LDAP dump for '.{domain}-{ext}.cache' ..." + Style.RESET_ALL)
	with open(f".{domain}-{ext}.cache","w") as f:
		f.write(str(dump))
		f.close()


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


def get_user_principal_name(cn, cn_upn_dict_list):
	user_cn = None
	for user in cn_upn_dict_list:
		if cn == user['CN']:
			user_cn = user['UserPrincipalName']
		else:
			continue
	return user_cn


# hound class

class Hound:
	def __init__(self, namingcontexts):
		self.namingcontexts = namingcontexts
		self.USERNAMES = []
		self.DOMAIN_ADMINS_UPN =[]
		self.DOMAIN_ADMINS_CN = []
		self.COMPUTERS = []
		self.ip_dict_list = []
		self.description_dict_list = []
		self.ou_list = []
		self.group_user_dict_list = []
		self.cn_upn_dict_list = []
		self.loot_list = []
		self.key_words = ['Pass','pass','pwd','Pwd','key','userPassword', 'secret']
		self.default_pwd_words = ["maxPwdAge","minPwdAge","minPwdLength","pwdProperties","pwdHistoryLength","badPwdCount","badPasswordTime","pwdLastSet"]
		self.special_words = ['Remote','Admin','Service']

	def dump_ldap(self):
		try:
			print(Fore.BLUE + f"[-] Connecting to the LDAP server at '{args.target}'..." + Style.RESET_ALL)
			connect = ldap.initialize(f"ldap://{args.target}")
			connect.set_option(ldap.OPT_REFERRALS, 0)
			connect.simple_bind_s(args.username, args.password)
			search_flt = "(objectClass=*)" # specific search filters
			page_size = 1000 # pagination setting (default highest value is 1000)
			searchreq_attrlist=[""] # specific attribute search
			req_ctrl = ldap.controls.SimplePagedResultsControl(criticality=True, size=page_size, cookie='')
			msgid = connect.search_ext(base=self.namingcontexts, scope=ldap.SCOPE_SUBTREE, serverctrls=[req_ctrl])
			total_results = []
			pages = 0
			while True: # loop over all of the pages using the same cookie, otherwise the search will fail
				pages += 1
				rtype, rdata, rmsgid, serverctrls = connect.result3(msgid)

				for obj in rdata:
					total_results.append(obj)

				pctrls = [c for c in serverctrls if c.controlType == ldap.controls.SimplePagedResultsControl.controlType]
				if pctrls:
					if pctrls[0].cookie: # Copy cookie from response control to request control
						req_ctrl.cookie = pctrls[0].cookie
						msgid = connect.search_ext(base=self.namingcontexts, scope=ldap.SCOPE_SUBTREE, serverctrls=[req_ctrl])
					else:
						break
				else:
					break

			if (total_results[0][1]) == {}:
				print(Fore.RED + "[!] Successful Bind but NO data returned - no permissions??" + Style.RESET_ALL)
				sys.exit()
				return None
			else:
				return total_results
				
		except ldap.INVALID_CREDENTIALS:
			print(Fore.RED + f"[!] Error - Invalid Credentials '{args.username}:{args.password}'" + Style.RESET_ALL)
			sys.exit()
		except ldap.INVALID_DN_SYNTAX as err:
			print(Fore.RED + f"[!] Error - Invalid Syntax: {err}" + Style.RESET_ALL)
			sys.exit()
		except Exception as err:
			print(Fore.RED + f"[!] Error - Failure binding to LDAP server\n {(err)}" + Style.RESET_ALL)
			sys.exit()

	def extract_all(self,dump):
		def create_cn_upn_dict_list(dump):
			# Map cn --> upn
			for row in dump:
				try:
					if b'person' in row[1]['objectClass']:
						# dictionary matches CN list to UserPrincipalName for use elsewhere
						upn_blist = (row[1]["userPrincipalName"])
						upn = upn_blist[0].decode('UTF-8')
						cn_upn_dict = {"CN":row[0],"UserPrincipalName":upn}
						self.cn_upn_dict_list.append(cn_upn_dict)
				except:
					pass

		# needed first for matching common names to principal names
		create_cn_upn_dict_list(dump)

		for row in dump:
			# users
			try:
				if b'person' in row[1]['objectClass']:
					user_principal_name_blist = row[1].get('userPrincipalName')
					if user_principal_name_blist:
						user_principal_name = user_principal_name_blist[0].decode('UTF-8')
						self.USERNAMES.append(user_principal_name)
					else:
						user_name_blist = row[1].get('sAMAccountName')
						user_name = user_name_blist[0].decode('UTF-8')
						self.USERNAMES.append(user_name)
			except:
				pass

			# Domain admins
			try:
				if b'group' in row[1]['objectClass'] and b'Domain Admins' in row[1]['cn']:
					member_blist = row[1]['member']
					self.DOMAIN_ADMINS_CN = [member.decode('UTF-8') for member in member_blist]
					for user_cn in self.DOMAIN_ADMINS_CN:
						user_upn = get_user_principal_name(user_cn, self.cn_upn_dict_list)
						if user_upn:
							self.DOMAIN_ADMINS_UPN.append(user_upn)
						else:
							self.DOMAIN_ADMINS_UPN.append(user_cn)
			except:
				pass

			# COMPUTERS
			try:
				if b'computer' in row[1]['objectClass']:
					# parse short cn
					cn_blist = (row[1]["cn"])
					cn = cn_blist[0].decode('UTF-8')
					if cn == 'self.COMPUTERS':
						pass
					else:
						self.COMPUTERS.append(cn)
			except:
				pass


			# Descriptions
			try:
				if b'person' in row[1]['objectClass']:
					upn_blist = row[1]['userPrincipalName']
					d_blist = row[1]['description']
					upn = upn_blist[0].decode('UTF-8')
					d = d_blist[0].decode('UTF-8')
					self.description_dict_list.append({"UserPrincipalName":upn, "description":d})
			except:
				pass


			# Groups
			if args.groups:
				try:
					if b'group' in row[1]['objectClass']:
						member_blist = row[1]['member']
						member_list = [i.decode('UTF-8') for i in member_blist]
						self.group_user_dict_list.append({'Group':row[0], 'Members':member_list})
				except:
					pass

			# OUs
			if args.org_unit:
				try:
					if b'organizationalUnit' in row[1].get('objectClass'):
						self.ou_list.append(row[0])
				except:
					pass

			# Search key phrases
			if args.keywords:
				try:
					for key in row[1]:
						# search keys
						if any(word in key for word in self.key_words):
							if key not in self.default_pwd_words:
								self.loot_list.append(f"{key}={(row[1].get(key))[0].decode('UTF-8')}")   # e.g. pwd=[b'p@$$w0rd']
						# search key values
						for item in row[1].get(key):
							try:
								item = item.decode('UTF-8')
								if any(word in item for word in self.key_words):
									self.loot_list.append(item)
							except:
								continue
				except:
					continue

		# return self.COMPUTERS, self.description_dict_list, self.cn_upn_dict_list, self.DOMAIN_ADMINS_CN, self.group_user_dict_list, self.ou_list, self.loot_list


	def print(self):
		# Print Hosts
		print(Fore.GREEN + "[+] Hosts" + Style.RESET_ALL)
		for i in range(len(self.ip_dict_list)):
			print(f"{self.ip_dict_list[i]['Name']} - {self.ip_dict_list[i]['Address']}")
		print('\n')

		# Print Domain Admins
		print(Fore.GREEN + "[+] Domain Admins" + Style.RESET_ALL)
		for user_upn in self.DOMAIN_ADMINS_UPN:
			print(user_upn)
		print('\n')

		# Print Users
		print(Fore.GREEN + "[+] Domain Users" + Style.RESET_ALL)
		for i in range(len(self.USERNAMES)):
			print(self.USERNAMES[i])

		print('\n')

		# Print Descriptions
		print(Fore.GREEN + "[+] Descriptions" + Style.RESET_ALL)
		for d in self.description_dict_list:
			print(f"{d['UserPrincipalName']} - {d['description']}")
		print('\n')

		# Print Groups
		if args.groups:
				print(Fore.GREEN + "[+] Group Memberships Found" + Style.RESET_ALL)
				for group in self.group_user_dict_list:
					if any(word in group['Group'] for word in self.special_words):
						print(Fore.RED + group['Group'] + Style.RESET_ALL)
					else:
						print(Fore.BLUE + group['Group'] + Style.RESET_ALL)

					# print members of group by upn name
					for cn in group['Members']:
						user_cn = get_user_principal_name(cn, self.cn_upn_dict_list)
						if user_cn:
							print(user_cn)
						else:
							print(cn)
					print('\n') 

		# Print OUs
		if args.org_unit:
			print(Fore.GREEN + "[+] Organizational Units Found" + Style.RESET_ALL)
			for ou in self.ou_list:
				print(ou)
			print('\n')


		# Print Passwords
		if args.keywords:
			print(Fore.GREEN + "[+] Key Strings" + Style.RESET_ALL)
			for l in self.loot_list:
				print(f"{l}")
			print('\n')


	def outfiles(self):
		# OUTFILES (optional)
		if args.output:

			with open(f"{args.output}-users.txt", "w") as f:
				for line in self.USERNAMES:
					f.write(line)
					f.write('\n')

			with open(f"{args.output}-domain_admins.txt", "w") as f:
				for line in self.DOMAIN_ADMINS_UPN:
					f.write(line)
					f.write('\n')

			with open(f"{args.output}-hosts.txt","w") as f:
				for line in range(len(self.ip_dict_list)):
					f.write(f"{self.ip_dict_list[line]['Name']} {self.ip_dict_list[line]['Address']}")
					f.write('\n')

			with open(f"{args.output}-descriptions.txt", "w") as f:
				for line in self.description_dict_list:
					f.write(f"{line['UserPrincipalName']} {line['description']}")
					f.write('\n')

			if args.groups:
				with open(f"{args.output}-groups.txt", "w") as f:
					for i in self.group_user_dict_list:
						f.write('\n')
						f.write(f"- {i['Group']}")
						# print members of group by upn name
						for cn in i['Members']:
							user_cn = get_user_principal_name(cn, self.cn_upn_dict_list)
							if user_cn:
								f.write('\n')
								f.write(user_cn)
							else:
								f.write('\n')
								f.write(cn)
						f.write('\n')

			if args.org_unit:
				with open(f"{args.output}-org.txt", "w") as f:
					for ou in self.ou_list:
						f.write('\n')
						f.write(ou)

			if args.keywords:
				with open(f"{args.output}-keywords.txt","w") as f:
					for l in self.loot_list:
						f.write(l)
						f.write('\n')



if __name__ == "__main__":
# hopefully easier to follow now :/

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

	# new hound object
	h1 = Hound(namingcontexts)

	# Check for cache
	cache = get_cache()

	# use cache otherwise new ldap dump
	if not cache:
		dump = h1.dump_ldap()
		create_cache(dump)
	else:
		dump = cache
	time.sleep(1.5)

	#extract all stuffs
	h1.extract_all(dump)

	# Resolve DNS names to IPv4
	h1.ip_dict_list = resolve_ipv4(h1.COMPUTERS)

	# Print stuff
	h1.print()

	# Output to files
	h1.outfiles()















