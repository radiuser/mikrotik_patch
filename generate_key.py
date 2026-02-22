from toyecc import *

def generate_eddsa_keypair():
    curve = getcurvebyname('Ed25519')
    private_key = ECPrivateKey.eddsa_generate(curve)
    return private_key.eddsa_encode(), private_key.pubkey.eddsa_encode()

def generate_kcdsa_keypair():
    curve = getcurvebyname('Curve25519')
    private_key = ECPrivateKey.generate(curve)
    return Tools.inttobytes_le(private_key.scalar, 32), Tools.inttobytes_le(int(private_key.pubkey.point.x), 32)

if __name__=='__main__':
    eddsa_private_key, eddsa_public_key = generate_eddsa_keypair()
    print(f"CUSTOM_NPK_SIGN_PRIVATE_KEY='{eddsa_private_key.hex().upper()}'")
    print(f"CUSTOM_NPK_SIGN_PUBLIC_KEY='{eddsa_public_key.hex().upper()}'")
    kcdsa_private_key, kcdsa_public_key = generate_kcdsa_keypair()
    print (f"CUSTOM_LICENSE_PRIVATE_KEY='{kcdsa_private_key.hex().upper()}'")
    print (f"CUSTOM_LICENSE_PUBLIC_KEY='{kcdsa_public_key.hex().upper()}'")
