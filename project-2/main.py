import zlib

from utils import *
from rsa_ecb import *
from rsa_cbc import *
from rsa_lib import *

# === Ogólna funkcja do testowania metod szyfrowania IDAT
def encrypt_idat(png_bytes, encrypt_fn):
    chunks = parse_chunks(png_bytes)
    new_chunks = []
    for typ, data, crc in chunks:
        if typ == b"IDAT":
            decompressed = zlib.decompress(data)
            encrypted = encrypt_fn(decompressed)
            recompressed = zlib.compress(encrypted)
            new_chunks.append((typ, recompressed, None))
        else:
            new_chunks.append((typ, data, crc))
    return build_png(new_chunks)


def decrypt_idat(png_bytes, decrypt_fn):
    chunks = parse_chunks(png_bytes)
    new_chunks = []
    for typ, data, crc in chunks:
        if typ == b"IDAT":
            decompressed = zlib.decompress(data)
            decrypted = decrypt_fn(decompressed)
            recompressed = zlib.compress(decrypted)
            new_chunks.append((typ, recompressed, None))
        else:
            new_chunks.append((typ, data, crc))
    return build_png(new_chunks)


# === Metoda druga: szyfrowanie skompresowanych danych
def encrypt_idat_compressed(png_bytes, encrypt_fn):
    chunks = parse_chunks(png_bytes)
    new_chunks = []
    for typ, data, crc in chunks:
        if typ == b"IDAT":
            encrypted = encrypt_fn(data)
            new_chunks.append((typ, encrypted, None))
        else:
            new_chunks.append((typ, data, crc))
    return build_png(new_chunks)


def decrypt_idat_compressed(png_bytes, decrypt_fn):
    chunks = parse_chunks(png_bytes)
    new_chunks = []
    for typ, data, crc in chunks:
        if typ == b"IDAT":
            decrypted = decrypt_fn(data)
            new_chunks.append((typ, decrypted, None))
        else:
            new_chunks.append((typ, data, crc))
    return build_png(new_chunks)


# === MAIN ===
if __name__ == "__main__":
    block_size = 50
    public_key, private_key, lib_pub, lib_priv = generate_keys(bits=1024)
    e, n = public_key
    d, _ = private_key

    with open("input.png", "rb") as f:
        original_bytes = f.read()

    # --- ECB ---
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

    # --- CBC ---
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

    # --- Library RSA (PKCS1_OAEP) ---
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

    # --- ECB bezpośrednio na danych skompresowanych ---
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

    # === Porównanie wyników ===
    compare_images("input.png", "ecb_decrypted.png")
    compare_images("input.png", "ecb_direct_decrypted.png")
    compare_images("input.png", "cbc_decrypted.png")
    compare_images("input.png", "lib_decrypted.png")
