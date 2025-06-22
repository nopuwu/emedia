from Crypto.PublicKey import RSA as CryptoRSA
from PIL import Image, ImageChops
import struct
import zlib


# Generacja kluczy RSA
def generate_keys(bits=2048):
    key = CryptoRSA.generate(bits)
    e = key.e
    d = key.d
    n = key.n
    pubkey = (e, n)
    privkey = (d, n)
    return pubkey, privkey, key.publickey(), key


# Porównanie obrazów
def compare_images(file1, file2):
    img1 = Image.open(file1).convert("RGB")
    img2 = Image.open(file2).convert("RGB")
    diff = ImageChops.difference(img1, img2)
    if diff.getbbox() is None:
        print(f"{file1} i {file2} są identyczne.")
    else:
        diff_pixels = sum(1 for p in diff.getdata() if p != (0, 0, 0))
        print(f"{file1} i {file2} różnią się. Różnych pikseli: {diff_pixels}")


# Parsowanie chunków
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
