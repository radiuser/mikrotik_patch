from mikro import *

def mikro_get_sofware_id(mbr_random:bytes,hdd_serial:str,hdd_model:str,hdd_capacity_MB:int)->str:
    '''HDD Device'''
    assert(isinstance(mbr_random, bytes) and len(mbr_random) == 12 )
    assert(isinstance(hdd_model, str))
    assert(isinstance(hdd_capacity_MB, int))
    mbr_sum = 0
    for i in range(0,10,2):
        mbr_sum += int.from_bytes(mbr_random[i:i+2], 'little')
    mbr_sum = ~mbr_sum & 0xFFFF if mbr_sum != 0 else 0xFFFF
    mbr_hash = int.from_bytes(mikro_sha256(mbr_random[:10])[:2], 'little')
    mbr_hash = mbr_hash if mbr_hash != 0 else 0x1EEF
    mbr_check = mbr_hash^mbr_sum
    assert(mbr_check ==int.from_bytes(mbr_random[10:12], 'little'))
    serial = hdd_serial.ljust(20,' ')[:20].encode()
    model = hdd_model.ljust(16,' ')[:16].encode()
    capacity = hdd_capacity_MB.to_bytes(4, 'little')
    data = serial + model + capacity
    data_hash = int.from_bytes(mikro_sha256(data)[:5], 'little') | 0x010000000000
    mbr_check =  0x03FF800F * (mbr_check & 0x07FF)
    id = mbr_check ^ data_hash
    return mikro_softwareid_encode(id)

def generate_license(software_id,private_key:bytes,version:int=6, level:int=6):
    assert(isinstance(private_key, bytes))
    if isinstance(software_id, str):software_id = mikro_softwareid_decode(software_id)
    lic = software_id.to_bytes(6, 'little')
    lic += version.to_bytes(1, 'little')
    lic += level.to_bytes(1, 'little')
    lic += b'\0'*8
    sig = mikro_kcdsa_sign(lic, private_key)
    lic = mikro_base64_encode(mikro_encode(lic)+sig,True)
    #return MIKRO_LICENSE_HEADER + '\n' + lic[:len(lic)//2] + '\n' + lic[len(lic)//2:] + '\n' + MIKRO_LICENSE_FOOTER
    return '\n-----BEGIN MIKROTIK SOFTWARE KEY------------\n' + lic[:len(lic)//2] + '\n' + lic[len(lic)//2:] + '\n-----END MIKROTIK SOFTWARE KEY--------------\n'

def prase_license(lic:str,public_key:bytes):
    assert(isinstance(public_key, bytes))
    #slic = lic.replace(MIKRO_LICENSE_HEADER, '').replace(MIKRO_LICENSE_FOOTER, '').replace('\n', '').replace(' ','')
    lic:bytes = mikro_base64_decode(lic)
    licVal = mikro_decode(lic[:16])
    software_id = int.from_bytes(licVal[:6], 'little')
    
    print(f"\nSoftware ID: {mikro_softwareid_encode(software_id)}({hex(software_id)})")
    print(f"RouterOS Version: {licVal[6]}")
    print(f"License Level: {licVal[7]}")
    nonce_hash = lic[16:32]
    print(f"Nonce Hash: {nonce_hash.hex()}")
    signature = lic[32:64]
    print(f"Signature: {signature.hex()}")
    print(f'License valid:{mikro_kcdsa_verify(licVal, nonce_hash+signature,public_key)}\n')

if __name__=='__main__':
    import argparse,os
    parser = argparse.ArgumentParser(description='MikroTik RouterOS License Generator')
    subparsers = parser.add_subparsers(dest="command")
    gen_parser = subparsers.add_parser('gen',help='Generator license by software id')
    gen_parser.add_argument('software_id',type=str, help='Sofware ID')
    gen_parser.add_argument('-pri','--privatekey',type=str,help='Private key,hex string')
    parse_parser = subparsers.add_parser('parse',help='Parse license')
    parse_parser.add_argument('lic',type=str, help='license string')
    parse_parser.add_argument('-pub','--publickey',type=str,help='Public key,hex string')
    args = parser.parse_args()
    if args.command=='gen':
        assert(args.software_id is not None)
        if args.privatekey:
            pri = bytes.fromhex(args.privatekey)
        else:
            pri = bytes.fromhex(os.environ['CUSTOM_LICENSE_PRIVATE_KEY'])
        print(generate_license(args.software_id, pri))
    elif args.command=='parse':
        if args.publickey:
            pub = bytes.fromhex(args.publickey)
        else:
            pub = bytes.fromhex(os.environ['CUSTOM_LICENSE_PUBLIC_KEY'])
        pub = bytes.fromhex(args.publickey)
        prase_license(args.lic, pub)
    else:
        parser.print_help()
		
