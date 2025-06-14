import os
import zlib
from sympy import randprime, mod_inverse
from random import randint

# -------------------- RSA --------------------

def generate_rsa_keys(bits=512):
    p = randprime(2**(bits//2 - 1), 2**(bits//2))
    q = randprime(2**(bits//2 - 1), 2**(bits//2))
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

def rsa_encrypt_block(m, pubkey):
    e, n = pubkey
    return pow(m, e, n)

def rsa_decrypt_block(c, privkey):
    d, n = privkey
    return pow(c, d, n)

def rsa_encrypt_data(data, pubkey, block_size=64):
    encrypted = bytearray()
    for i in range(0, len(data), block_size):
        block = int.from_bytes(data[i:i+block_size], byteorder='big')
        enc = rsa_encrypt_block(block, pubkey)
        enc_bytes = enc.to_bytes((pubkey[1].bit_length() + 7) // 8, byteorder='big')
        encrypted.extend(enc_bytes)
    return bytes(encrypted)

def rsa_decrypt_data(data, privkey, block_size=64):
    decrypted = bytearray()
    enc_block_size = (privkey[1].bit_length() + 7) // 8
    for i in range(0, len(data), enc_block_size):
        block = int.from_bytes(data[i:i+enc_block_size], byteorder='big')
        dec = rsa_decrypt_block(block, privkey)
        dec_bytes = dec.to_bytes(block_size, byteorder='big')
        decrypted.extend(dec_bytes)
    return bytes(decrypted)

# -------------------- PNG Utilities --------------------

def extract_idat_chunks(png_data):
    pos = 8  # skip signature
    idat_data = bytearray()
    other_chunks = []

    while pos < len(png_data):
        length = int.from_bytes(png_data[pos:pos+4], 'big')
        chunk_type = png_data[pos+4:pos+8]
        chunk_data = png_data[pos+8:pos+8+length]
        crc = png_data[pos+8+length:pos+12+length]

        if chunk_type == b'IDAT':
            idat_data += chunk_data
        else:
            other_chunks.append((chunk_type, chunk_data, crc))

        pos += length + 12

    return idat_data, other_chunks

def reassemble_png(header, other_chunks, encrypted_data):
    result = bytearray()
    result += header

    for ctype, cdata, crc in other_chunks:
        result += len(cdata).to_bytes(4, 'big')
        result += ctype
        result += cdata
        result += crc

        if ctype == b'IHDR':
            # insert encrypted IDAT chunk after IHDR
            comp_data = zlib.compress(encrypted_data)
            result += len(comp_data).to_bytes(4, 'big')
            result += b'IDAT'
            result += comp_data
            crc_val = zlib.crc32(b'IDAT' + comp_data)
            result += crc_val.to_bytes(4, 'big')

    result += b'\x00\x00\x00\x00IEND\xAE\x42\x60\x82'
    return result

# -------------------- Main --------------------

def process_png(input_path, output_enc, output_dec):
    with open(input_path, 'rb') as f:
        png = f.read()

    header = png[:8]
    idat_data, other_chunks = extract_idat_chunks(png)
    decompressed = zlib.decompress(idat_data)

    pub, priv = generate_rsa_keys(512)
    enc_data = rsa_encrypt_data(decompressed, pub)
    dec_data = rsa_decrypt_data(enc_data, priv)

    png_enc = reassemble_png(header, other_chunks, enc_data)
    png_dec = reassemble_png(header, other_chunks, dec_data)

    with open(output_enc, 'wb') as f:
        f.write(png_enc)
    with open(output_dec, 'wb') as f:
        f.write(png_dec)

# Example:
process_png("input.png", "encrypted.png", "decrypted.png")
