"""
This script allows us to add a user to a group using LDAP, which is useful when we have the privilege to add users to a group, but we are not admins on the Domain Controller.

Author: @JulioUrena
License: GPL-3.0 license
"""

import argparse
import sys
from ldap3 import Server, Connection, ALL, NTLM, MODIFY_ADD, MODIFY_REPLACE, MODIFY_DELETE

parser = argparse.ArgumentParser(description='Add a user to an Active Directory group.')
parser.add_argument('-d','--domain', required=True, help='The domain name of the Active Directory server.')
parser.add_argument('-g','--group', required=True, help='The name of the group to add the user to.')
parser.add_argument('-a','--adduser', required=True, help='The username of the user to add.')
parser.add_argument('-u','--user', required=True, help='The username of an Active Directory user with AddMember privilege.')
parser.add_argument('-p','--password', required=True, help='The password of the Active Directory user.')

args = parser.parse_args()

domain_name = args.domain
group_name = args.group
user_name = args.adduser
ad_username = args.user
ad_password = args.password

search_base = 'dc=' + ',dc='.join(domain_name.split('.'))

server = Server(domain_name, get_info=ALL)
conn = Connection(
    server,
    user=f'{domain_name}\\{ad_username}',
    password=ad_password,
    authentication=NTLM
)

if conn.bind():
    print('[+] Connected to Active Directory successfully.')
else:
    print('[-] Error: failed to bind to the Active Directory server.')
    sys.exit(1)


conn.search(
    search_base=search_base,
    search_filter=f'(&(objectClass=group)(cn={group_name}))',
    attributes=['member']
)

if conn.entries:
    print('[+] Group ' + group_name + ' found.')
else:
    print('[-] Error: group not found.')
    sys.exit(1)

group_dn = conn.entries[0].entry_dn
members = conn.entries[0].member.values

conn.search(
    search_base=search_base,
    search_filter=f'(&(objectClass=user)(sAMAccountName={user_name}))',
    attributes=['distinguishedName']
)

if conn.entries:
    print('[+] User ' + user_name + ' found.')
else:
    print('[-] Error: user not found.')
    sys.exit(1)

user_dn = conn.entries[0].distinguishedName.value

if user_dn in members:
    print('[+] User is already a member of the group.')
else:
    if conn.modify(
        dn=group_dn,
        changes={'member': [(MODIFY_ADD, [user_dn])]}
    ):
        print('[+] User added to group successfully.')
    else:
        print('[-] There was an error trying to add the user to the group.')
