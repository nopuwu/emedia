from utils import xor_bytes
import os


# CBC
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
        if len(block) < block_out:
            break
        c = int.from_bytes(block, "big")
        m = pow(c, d, n)
        m_bytes = m.to_bytes(block_size, "big")
        plain = xor_bytes(m_bytes, prev)
        decrypted.extend(plain)
        prev = block  # ✅ POPRAWKA: użyj całego zaszyfrowanego bloku
    return decrypted
