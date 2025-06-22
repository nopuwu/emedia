import zlib

from utils import *
from rsa_ecb import *
from rsa_cbc import *
from rsa_lib import *
from idat import *


if __name__ == "__main__":
    block_size = 100
    public_key, private_key, lib_pub, lib_priv = generate_keys(2048)
    e, n = public_key
    d, _ = private_key

    with open("input.png", "rb") as f:
        original_bytes = f.read()

    # ECB
    ecb_encrypted = encrypt_idat(
        original_bytes, lambda data: rsa_ecb_encrypt(data, block_size, e, n)
    )
    ecb_decrypted = decrypt_idat(
        ecb_encrypted, lambda data: rsa_ecb_decrypt(data, block_size, d, n)
    )
    with open("ecb_encrypted.png", "wb") as f:
        f.write(ecb_encrypted)
    with open("ecb_decrypted.png", "wb") as f:
        f.write(ecb_decrypted)

    # CBC
    cbc_encrypted = encrypt_idat(
        original_bytes, lambda data: rsa_cbc_encrypt(data, block_size, e, n)
    )
    cbc_decrypted = decrypt_idat(
        cbc_encrypted, lambda data: rsa_cbc_decrypt(data, block_size, d, n)
    )
    with open("cbc_encrypted.png", "wb") as f:
        f.write(cbc_encrypted)
    with open("cbc_decrypted.png", "wb") as f:
        f.write(cbc_decrypted)

    # RSA z biblioteki
    lib_encrypted = encrypt_idat(
        original_bytes, lambda data: rsa_encrypt_lib(data, lib_pub)
    )
    lib_decrypted = decrypt_idat(
        lib_encrypted, lambda data: rsa_decrypt_lib(data, lib_priv)
    )
    with open("lib_encrypted.png", "wb") as f:
        f.write(lib_encrypted)
    with open("lib_decrypted.png", "wb") as f:
        f.write(lib_decrypted)

    # ECB bezpośrednio na danych skompresowanych
    ecb_direct_encrypted = encrypt_idat_compressed(
        original_bytes, lambda data: rsa_ecb_encrypt(data, block_size, e, n)
    )
    ecb_direct_decrypted = decrypt_idat_compressed(
        ecb_direct_encrypted, lambda data: rsa_ecb_decrypt(data, block_size, d, n)
    )
    with open("ecb_direct_encrypted.png", "wb") as f:
        f.write(ecb_direct_encrypted)
    with open("ecb_direct_decrypted.png", "wb") as f:
        f.write(ecb_direct_decrypted)

    # Porównanie wyników
    compare_images("input.png", "ecb_decrypted.png")
    compare_images("input.png", "ecb_direct_decrypted.png")
    compare_images("input.png", "cbc_decrypted.png")
    compare_images("input.png", "lib_decrypted.png")
