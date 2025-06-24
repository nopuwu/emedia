import os
from Crypto.PublicKey import RSA as CryptoRSA
from Crypto.Cipher import PKCS1_OAEP
from PIL import Image, ImageChops
import struct
import zlib


def rsa_ecb_encrypt(data, block_size_in, e, n):
    """Szyfruje dane blokowo w trybie ECB z użyciem RSA."""
    block_size_out = (n.bit_length() + 7) // 8
    encrypted = bytearray()
    for i in range(0, len(data), block_size_in):
        block = data[i : i + block_size_in]
        if len(block) < block_size_in: # padding
            block += b"\x00" * (block_size_in - len(block))
        m = int.from_bytes(block, "big")
        c = pow(m, e, n)
        c_bytes = c.to_bytes(block_size_out, "big")
        encrypted.extend(c_bytes)
    return encrypted


def rsa_ecb_decrypt(data, block_size_in, d, n):
    """Deszyfruje dane RSA w trybie ECB."""
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


def rsa_cbc_encrypt(data, block_size, e, n, iv=None):
    """Szyfruje dane RSA w trybie CBC."""
    block_out = (n.bit_length() + 7) // 8
    if iv is None:
        iv = os.urandom(block_size)
    encrypted = bytearray(iv)
    prev = iv
    for i in range(0, len(data), block_size):
        block = data[i : i + block_size]
        if len(block) < block_size: # padding
            block += b"\x00" * (block_size - len(block))
        xored = xor_bytes(block, prev[:block_size])
        m = int.from_bytes(xored, "big")
        c = pow(m, e, n)
        c_bytes = c.to_bytes(block_out, "big")
        encrypted.extend(c_bytes)
        prev = c_bytes
    return encrypted


def rsa_cbc_decrypt(data, block_size, d, n):
    """Deszyfruje dane RSA zaszyfrowane w trybie CBC."""
    block_out = (n.bit_length() + 7) // 8
    iv = data[:block_size]
    prev = iv
    decrypted = bytearray()
    for i in range(block_size, len(data), block_out):
        block = data[i : i + block_out]
        if len(block) < block_out:
            break
        c = int.from_bytes(block, "big")
        m = pow(c, d, n)
        m_bytes = m.to_bytes(block_size, "big")
        plain = xor_bytes(m_bytes, prev[:block_size])
        decrypted.extend(plain)
        prev = block
    return decrypted


def rsa_encrypt_lib(data, pubkey):
    """Szyfruje dane za pomocą biblioteki PKCS1_OAEP."""
    cipher = PKCS1_OAEP.new(pubkey)
    block_size = pubkey.size_in_bytes() - 42
    encrypted = bytearray()
    for i in range(0, len(data), block_size):
        block = data[i : i + block_size]
        encrypted.extend(cipher.encrypt(block))
    return encrypted


def rsa_decrypt_lib(data, privkey):
    """Deszyfruje dane RSA za pomocą PKCS1_OAEP."""
    cipher = PKCS1_OAEP.new(privkey)
    block_size = privkey.size_in_bytes()
    decrypted = bytearray()
    for i in range(0, len(data), block_size):
        block = data[i : i + block_size]
        decrypted.extend(cipher.decrypt(block))
    return decrypted


def encrypt_idat(png_bytes, encrypt_fn):
    """Szyfruje tylko dane IDAT (po dekompresji) w pliku PNG."""
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
    """Deszyfruje dane IDAT (po dekompresji) w pliku PNG."""
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


def encrypt_idat_compressed(png_bytes, encrypt_fn):
    """Szyfruje dane IDAT bez dekompresji (na skompresowanych danych)."""
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
    """Deszyfruje dane IDAT bez dekompresji (na skompresowanych danych)."""
    chunks = parse_chunks(png_bytes)
    new_chunks = []
    for typ, data, crc in chunks:
        if typ == b"IDAT":
            decrypted = decrypt_fn(data)
            new_chunks.append((typ, decrypted, None))
        else:
            new_chunks.append((typ, data, crc))
    return build_png(new_chunks)


def generate_keys(bits=2048):
    """Generuje parę kluczy RSA o podanej długości bitów."""
    key = CryptoRSA.generate(bits)
    e = key.e
    d = key.d
    n = key.n
    pubkey = (e, n)
    privkey = (d, n)
    return pubkey, privkey, key.publickey(), key


def compare_images(file1, file2):
    """Porównuje dwa obrazy PNG piksel po pikselu i wyświetla różnice."""
    img1 = Image.open(file1).convert("RGBA")
    img2 = Image.open(file2).convert("RGBA")
    diff = ImageChops.difference(img1, img2)
    if diff.getbbox() is None:
        print(f"{file1} i {file2} są identyczne.")
    else:
        diff_pixels = sum(1 for p in diff.getdata() if p != (0, 0, 0))
        print(f"{file1} i {file2} różnią się. Różnych pikseli: {diff_pixels}")


def parse_chunks(png_bytes):
    """Parsuje bajty PNG i zwraca listę chunków jako (typ, dane, crc)."""
    chunks = []
    offset = 8  # do pominięcia sygnatury PNG
    while offset < len(png_bytes):
        length = struct.unpack(">I", png_bytes[offset : offset + 4])[0]
        chunk_type = png_bytes[offset + 4 : offset + 8]
        data = png_bytes[offset + 8 : offset + 8 + length]
        crc = png_bytes[offset + 8 + length : offset + 12 + length]
        chunks.append((chunk_type, data, crc))
        offset += length + 12
    return chunks


def build_png(chunks):
    """Buduje plik PNG z listy chunków."""
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
    """Zwraca wynik operacji XOR pomiędzy bajtami a i b."""
    return bytes(x ^ y for x, y in zip(a, b))


if __name__ == "__main__":
    file = "input.png"
    output_dir = "output"
    block_size = 100
    public_key, private_key, lib_pub, lib_priv = generate_keys(2048)
    e, n = public_key
    d, _ = private_key

    with open(file, "rb") as f:
        original_bytes = f.read()
        if original_bytes[:8] != b"\x89PNG\r\n\x1a\n":
            raise ValueError("To nie jest prawidłowy plik PNG")

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # ECB
    ecb_encrypted = encrypt_idat(
        original_bytes, lambda data: rsa_ecb_encrypt(data, block_size, e, n)
    )
    ecb_decrypted = decrypt_idat(
        ecb_encrypted, lambda data: rsa_ecb_decrypt(data, block_size, d, n)
    )
    with open(f"{output_dir}/ecb_encrypted.png", "wb") as f:
        f.write(ecb_encrypted)
    with open(f"{output_dir}/ecb_decrypted.png", "wb") as f:
        f.write(ecb_decrypted)

    # CBC
    cbc_encrypted = encrypt_idat(
        original_bytes, lambda data: rsa_cbc_encrypt(data, block_size, e, n)
    )
    cbc_decrypted = decrypt_idat(
        cbc_encrypted, lambda data: rsa_cbc_decrypt(data, block_size, d, n)
    )
    with open(f"{output_dir}/cbc_encrypted.png", "wb") as f:
        f.write(cbc_encrypted)
    with open(f"{output_dir}/cbc_decrypted.png", "wb") as f:
        f.write(cbc_decrypted)

    # RSA z biblioteki
    lib_encrypted = encrypt_idat(
        original_bytes, lambda data: rsa_encrypt_lib(data, lib_pub)
    )
    lib_decrypted = decrypt_idat(
        lib_encrypted, lambda data: rsa_decrypt_lib(data, lib_priv)
    )
    with open(f"{output_dir}/lib_encrypted.png", "wb") as f:
        f.write(lib_encrypted)
    with open(f"{output_dir}/lib_decrypted.png", "wb") as f:
        f.write(lib_decrypted)

    # ECB bezpośrednio na skompresowanych danych
    ecb_direct_encrypted = encrypt_idat_compressed(
        original_bytes, lambda data: rsa_ecb_encrypt(data, block_size, e, n)
    )
    ecb_direct_decrypted = decrypt_idat_compressed(
        ecb_direct_encrypted, lambda data: rsa_ecb_decrypt(data, block_size, d, n)
    )
    with open(f"{output_dir}/ecb_direct_encrypted.png", "wb") as f:
        f.write(ecb_direct_encrypted)
    with open(f"{output_dir}/ecb_direct_decrypted.png", "wb") as f:
        f.write(ecb_direct_decrypted)

    # Porównanie wyników
    compare_images("input.png", f"{output_dir}/ecb_decrypted.png")
    compare_images("input.png", f"{output_dir}/ecb_direct_decrypted.png")
    compare_images("input.png", f"{output_dir}/cbc_decrypted.png")
    compare_images("input.png", f"{output_dir}/lib_decrypted.png")
