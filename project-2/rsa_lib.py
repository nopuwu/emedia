from Crypto.Cipher import PKCS1_OAEP


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
