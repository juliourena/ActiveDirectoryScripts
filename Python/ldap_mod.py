#!/usr/bin/env python3

#This script allows us to add a user to a group using LDAP, which is useful when we have the privilege to add users to a group, but we are not admins 
#on the Domain Controller.

#Author: @JulioUrena
#License: GPL-3.0 license

# When testing with TLS, add following line to ldap.conf file on client server:
# TLS_REQCERT never

# Import necessary modules
import argparse
import sys
from ldap3 import Server, Connection, ALL, NTLM, MODIFY_ADD, MODIFY_REPLACE, MODIFY_DELETE



# Parse command-line arguments
parser = argparse.ArgumentParser(description='Add or remove user to an Active Directory group.')
parser.add_argument('-d','--domain', required=True, help='The domain name of the Active Directory server.')
parser.add_argument('-g','--group', required=False, help='The name of the group to add the user to.')
parser.add_argument('-a','--adduser', required=False, help='The username of the user to add.')
parser.add_argument('-r','--removeuser', required=False, help='The username of the user to add.')
parser.add_argument('-c','--createuser', required=False, help='The username of the user to create.')
parser.add_argument('--deleteuser', required=False, help='The username of the user to delete.')
parser.add_argument('--addspn', required=False, help='Register valid target user to an SPN.')
parser.add_argument('--deletespn', required=False, help='Delete SPN registration for a valid target user.')
parser.add_argument('-u','--user', required=True, help='The username of an Active Directory user with AddMember privilege.')
parser.add_argument('-p','--password', required=True, help='The password of the Active Directory user.')
args = parser.parse_args()



def __populate_search_user(conn, user_name, search_base):
    conn.search(
        search_base=search_base,
        search_filter=f'(&(objectClass=user)(SAMAccountName={user_name}))',
        attributes=['distinguishedName']
    )

    return conn



def __populate_search_group(conn, group_name, search_base):
    conn.search(
        search_base=search_base,
        search_filter=f'(&(objectClass=group)(sAMAccountName={group_name}))',
        attributes=['member']
    )

    return conn
    


def __find_user(conn, user_name):
    # Check if the user was found
    if conn.entries:
        print('[+] User ' + user_name + ' found.')
    elif not conn.entries and args.createuser:
        print('[+] Checked if user already exists. Now creating user.')
    else:
        print('[-] Error: user not found.')
        sys.exit(1)



def __find_group(conn, group_name):
    # Check if the group was found
    if conn.entries:
        print('[+] Group ' + group_name + ' found.')
    else:
        print('[-] Error: group not found.')
        sys.exit(1)



def __checks_and_variables(conn, user_name, search_base):
    # Group to modify
    group_name = args.group

    # Generally populate conn object
    __populate_search_user(conn, user_name, search_base)

    # Find user
    __find_user(conn, user_name)

    # Extract the user's DN
    user_dn = conn.entries[0].distinguishedName.value

    # Generally populate conn object
    __populate_search_group(conn, group_name, search_base)

    # Find group
    __find_group(conn, group_name)

    # Extract DN of group
    group_dn = conn.entries[0].entry_dn

    return group_dn, user_dn, group_name



def __add_user(conn, user_dn, group_dn, user_name, search_base):
    conn.search(
        search_base=search_base,
        search_filter=f'(&(objectClass=group)(cn={group_name}))',
        attributes=['member']
    )
    
    # Add user
    if conn.modify(
            dn=group_dn,
            changes={'member': [(MODIFY_ADD), [user_dn]]}
    ): print('[+] User ' + user_name + ' successfully added.')
    else:
        print('[-] User might already be in group, or perhaps you lack permissions.')



def __remove_user(conn, user_dn, group_dn, user_name, search_base):
    # Search for the group with the given name
    conn.search(
        search_base=search_base,
        search_filter=f'(&(objectClass=group)(cn={group_name}))',
        attributes=['member']
    )
    
    # Remove user
    if conn.modify(
            dn=group_dn,
            changes={'member': [(MODIFY_DELETE), [user_dn]]}
    ): print('[+] User ' + user_name + ' successfully removed.')
    else:
        print('[-] User might not be in group, or perhaps you lack permissions.')



def __create_user(conn, user_name, search_base):
    if conn.add(
            f"cn={user_name},CN=Users,{search_base}",
            attributes = {"objectclass":"user"}
    ): print('[+] User ' + user_name + ' successfully created.')
    else:
        print('[-] User might already exist, or perhaps you lack permissions.')

    # Need to change samaccountname from default.
    if conn.modify(
            f"cn={user_name},CN=Users,{search_base}",
            changes={'samaccountname': [(MODIFY_REPLACE, [f'{user_name}'])]}
            ): print('[+] Successfully changed samaccountname from default.')
   


def __delete_user(conn, user_name, search_base):
    if conn.delete(
            f"cn={user_name},CN=Users,{search_base}"
    ): print('[+] User ' + user_name + ' successfully deleted.')
    else:
        print('[-] User might not exist, or perhaps you lack permissions.')



def __add_spn(conn, user_name, search_base):
    # Generally populate conn object
    __populate_search_user(conn, user_name, search_base)

    # Find user
    __find_user(conn, user_name)

    # Extract the user's DN
    user_dn = conn.entries[0].distinguishedName.value

    if conn.modify(
            user_dn,
            changes={'servicePrincipalName': [(MODIFY_ADD, ['test/test.test'])]}
            ): print('[+] Successfully registered user ' + user_name + ' to an SPN.')
    else:
        print('[-] User may already be registered to an SPN, or you lack permissions.')



def __delete_spn(conn, user_name, search_base):
    # Generally populate conn object
    __populate_search_user(conn, user_name, search_base)

    # Find user
    __find_user(conn, user_name)

    # Extract the user's DN
    user_dn = conn.entries[0].distinguishedName.value

    if conn.modify(
            user_dn,
            changes={'servicePrincipalName': [(MODIFY_DELETE, ['test/test.test'])]}
            ): print('[+] Successfully deleted SPN for ' + user_name + '.')
    else:
        print('[-] User may not be registered to an SPN, or you lack permissions.')



if __name__ == '__main__':
    # Extract values from command-line arguments
    domain_name = args.domain
    ad_username = args.user
    ad_password = args.password

    # Construct the search base from the domain name
    search_base = 'dc=' + ',dc='.join(domain_name.split('.'))

    # Create a connection to the Active Directory server
    server = Server(domain_name, get_info=ALL)
    conn = Connection(
        server,
        user=f'{domain_name}\\{ad_username}',
        password=ad_password,
        authentication=NTLM
    )

    # Bind to the server with the given credentials
    if conn.bind():
        print('[+] Connected to Active Directory successfully.')
    else:
        print('[-] Error: failed to bind to the Active Directory server.')
        sys.exit(1)

    if args.adduser:
        # Populate user_name with target user
        user_name = args.adduser

        # Perform checks and Populate variables
        group_dn, user_dn, group_name = __checks_and_variables(conn, user_name, search_base)

        # Add user to target group
        __add_user(conn, user_dn, group_dn, user_name, search_base)

    elif args.removeuser: 
        # Populate user_name with target user
        user_name = args.removeuser

        # Perform checks and Populate variables
        group_dn, user_dn, group_name = __checks_and_variables(conn, user_name, search_base)

        # Remove user from target group
        __remove_user(conn, user_dn, group_dn, user_name, search_base)

    elif args.createuser:
        # Populate user_name with target user
        user_name = args.createuser

        # Create target user
        __create_user(conn, user_name, search_base)

    elif args.deleteuser:
        # Populate user_name with target user
        user_name = args.deleteuser

        # Delete target user
        __delete_user(conn, user_name, search_base)

    elif args.addspn:
        # Populate user_name with target user
        user_name = args.addspn

        # Register target user to SPN test/test.local
        __add_spn(conn, user_name, search_base)

    elif args.deletespn:
        # Populate user_name with target user
        user_name = args.deletespn

        # Delete SPN for target user
        __delete_spn(conn, user_name, search_base)

