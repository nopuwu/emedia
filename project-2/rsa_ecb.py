def rsa_ecb_encrypt(data, block_size_in, e, n):
    """Szyfruje dane blokowo w trybie ECB z użyciem RSA."""
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
