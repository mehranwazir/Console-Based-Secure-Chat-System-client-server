from app.crypto.dh import *

# client side
a = dh_generate_private()
A = dh_public_value(a)

# server side
b = dh_generate_private()
B = dh_public_value(b)

# compute secrets
Ks_client = dh_shared_secret(B, a)
Ks_server = dh_shared_secret(A, b)

print("Shared ints match:", Ks_client == Ks_server)

# derive keys
Kc = derive_aes_key(Ks_client)
Ks = derive_aes_key(Ks_server)

print("AES keys match:", Kc == Ks)
