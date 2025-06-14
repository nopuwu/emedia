import os
from Crypto.PublicKey import RSA as CryptoRSA
from Crypto.Cipher import PKCS1_OAEP
from PIL import Image, ImageChops
import struct
import zlib


# === RSA Key Generation ===
def generate_keys(bits=1024):
    key = CryptoRSA.generate(bits)
    e = key.e
    d = key.d
    n = key.n
    pubkey = (e, n)
    privkey = (d, n)
    return pubkey, privkey, key.publickey(), key


# === RSA ECB Mode (własna) ===
def rsa_ecb_encrypt(data, block_size_in, e, n):
    block_size_out = (n.bit_length() + 7) // 8
    encrypted = bytearray()
    for i in range(0, len(data), block_size_in):
        block = data[i : i + block_size_in]
        if len(block) < block_size_in:
            block += b"\x00" * (block_size_in - len(block))
        m = int.from_bytes(block, "big")
        c = pow(m, e, n)
        c_bytes = c.to_bytes(block_size_out, "big")
        encrypted.extend(c_bytes)
    return encrypted


def rsa_ecb_decrypt(data, block_size_in, d, n):
    block_size_out = (n.bit_length() + 7) // 8
    decrypted = bytearray()
    for i in range(0, len(data), block_size_out):
        block = data[i : i + block_size_out]
        if len(block) < block_size_out:
            break
        c = int.from_bytes(block, "big")
        m = pow(c, d, n)
        m_bytes = m.to_bytes(block_size_in, "big")
        decrypted.extend(m_bytes)
    return decrypted


# === RSA CBC Mode (własna) ===
def rsa_cbc_encrypt(data, block_size, e, n, iv=None):
    block_out = (n.bit_length() + 7) // 8
    if iv is None:
        iv = os.urandom(block_size)
    encrypted = bytearray(iv)
    prev = iv
    for i in range(0, len(data), block_size):
        block = data[i : i + block_size]
        if len(block) < block_size:
            block += b"\x00" * (block_size - len(block))
        xored = xor_bytes(block, prev)
        m = int.from_bytes(xored, "big")
        c = pow(m, e, n)
        c_bytes = c.to_bytes(block_out, "big")
        encrypted.extend(c_bytes)
        prev = c_bytes[:block_size]
    return encrypted


def rsa_cbc_decrypt(data, block_size, d, n):
    block_out = (n.bit_length() + 7) // 8
    iv = data[:block_size]
    prev = iv
    decrypted = bytearray()
    for i in range(block_size, len(data), block_out):
        block = data[i : i + block_out]
        c = int.from_bytes(block, "big")
        m = pow(c, d, n)
        m_bytes = m.to_bytes(block_size, "big")
        plain = xor_bytes(m_bytes, prev)
        decrypted.extend(plain)
        prev = block[:block_size]
    return decrypted


# === RSA z biblioteki ===
def rsa_encrypt_lib(data, pubkey):
    cipher = PKCS1_OAEP.new(pubkey)
    block_size = pubkey.size_in_bytes() - 42
    encrypted = bytearray()
    for i in range(0, len(data), block_size):
        block = data[i : i + block_size]
        encrypted.extend(cipher.encrypt(block))
    return encrypted


def rsa_decrypt_lib(data, privkey):
    cipher = PKCS1_OAEP.new(privkey)
    block_size = privkey.size_in_bytes()
    decrypted = bytearray()
    for i in range(0, len(data), block_size):
        block = data[i : i + block_size]
        decrypted.extend(cipher.decrypt(block))
    return decrypted


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


# === Porównanie obrazów
def compare_images(file1, file2):
    img1 = Image.open(file1).convert("RGB")
    img2 = Image.open(file2).convert("RGB")
    diff = ImageChops.difference(img1, img2)
    if diff.getbbox() is None:
        print(f"{file1} i {file2} są identyczne.")
    else:
        diff_pixels = sum(1 for p in diff.getdata() if p != (0, 0, 0))
        print(f"{file1} i {file2} różnią się. Różnych pikseli: {diff_pixels}")


# === PNG Chunk Helpers ===
def parse_chunks(png_bytes):
    chunks = []
    offset = 8  # skip PNG signature
    while offset < len(png_bytes):
        length = struct.unpack(">I", png_bytes[offset : offset + 4])[0]
        chunk_type = png_bytes[offset + 4 : offset + 8]
        data = png_bytes[offset + 8 : offset + 8 + length]
        crc = png_bytes[offset + 8 + length : offset + 12 + length]
        chunks.append((chunk_type, data, crc))
        offset += length + 12
    return chunks


def build_png(chunks):
    sig = b"\x89PNG\r\n\x1a\n"
    png = bytearray(sig)
    for chunk_type, data, _ in chunks:
        length = len(data)
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        png.extend(struct.pack(">I", length))
        png.extend(chunk_type)
        png.extend(data)
        png.extend(struct.pack(">I", crc))
    return png


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


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
