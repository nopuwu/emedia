import zlib
from utils import build_png, parse_chunks


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
