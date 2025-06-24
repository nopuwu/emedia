from Crypto.PublicKey import RSA as CryptoRSA
from PIL import Image, ImageChops
import struct
import zlib


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
