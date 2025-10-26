#!/usr/bin/env python3
"""
tugas2_des_comm.py

Satu file Python yang berisi:
- Implementasi DES (ECB, PKCS#7 padding) — pendidikan
- Simulasi 2 device (Device A dan Device B) yang saling berkirim pesan:
    Device A --(encrypt with K_AB)--> Device B (decrypt with K_AB)
    Device B --(encrypt with K_BA)--> Device A (decrypt with K_BA)
- Output menampilkan langkah enkripsi/dekripsi dan hex cipher
- Bisa langsung di-push ke GitHub

Cara pakai (contoh):
$ python3 tugas2_des_comm.py

Catatan: Implementasi DES ini murni untuk pembelajaran. Jangan gunakan untuk produksi.
"""

from typing import Callable
import sys

# ---------------------
# Minimal DES (educational)
# ---------------------
IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
LEFT_SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

S_BOXES = [
[[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
[[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
[[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
[[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
[[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
[[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8]],
[[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
[[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]

def _bits_from_int(x, bits):
    return [(x >> (bits-1-i)) & 1 for i in range(bits)]

def _int_from_bits(bits):
    x = 0
    for b in bits:
        x = (x << 1) | (b & 1)
    return x

def _permute(block, table):
    return [block[i-1] for i in table]

def _left_rotate(lst, n):
    return lst[n:] + lst[:n]

def _generate_subkeys(key64bits):
    key_bits = _bits_from_int(key64bits, 64)
    permuted = _permute(key_bits, PC1)
    c = permuted[:28]
    d = permuted[28:]
    subkeys = []
    for shift in LEFT_SHIFTS:
        c = _left_rotate(c, shift)
        d = _left_rotate(d, shift)
        cd = c + d
        subkey_bits = _permute(cd, PC2)
        subkeys.append(_int_from_bits(subkey_bits))
    return subkeys

def _feistel(r32_int, subkey48):
    r_bits = _bits_from_int(r32_int, 32)
    e_bits = _permute(r_bits, E)
    e_int = _int_from_bits(e_bits)
    x = e_int ^ subkey48
    out32_bits = []
    for i in range(8):
        six = (x >> (42 - 6*i)) & 0x3F
        row = ((six & 0x20) >> 4) | (six & 1)
        col = (six >> 1) & 0xF
        s_val = S_BOXES[i][row][col]
        out32_bits.extend(_bits_from_int(s_val, 4))
    p_bits = _permute(out32_bits, P)
    return _int_from_bits(p_bits)

def encrypt_block(block8, subkeys):
    bits = []
    for b in block8:
        bits.extend(_bits_from_int(b,8))
    permuted = _permute(bits, IP)
    L = _int_from_bits(permuted[:32])
    R = _int_from_bits(permuted[32:])
    for i in range(16):
        f = _feistel(R, subkeys[i])
        L, R = R, L ^ f
    preoutput_bits = _bits_from_int(R,32) + _bits_from_int(L,32)
    final_bits = _permute(preoutput_bits, FP)
    out = bytearray()
    for i in range(0,64,8):
        out.append(_int_from_bits(final_bits[i:i+8]))
    return bytes(out)

def decrypt_block(block8, subkeys):
    return encrypt_block(block8, list(reversed(subkeys)))

def pad_pkcs7(data: bytes, block_size=8):
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len])*pad_len

def unpad_pkcs7(data: bytes):
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len])*pad_len:
        raise ValueError("Invalid PKCS7 padding")
    return data[:-pad_len]

def encrypt_bytes(plaintext: bytes, key_hex: str) -> bytes:
    key = int(key_hex, 16)
    subkeys = _generate_subkeys(key)
    padded = pad_pkcs7(plaintext, 8)
    out = bytearray()
    for i in range(0, len(padded), 8):
        block = padded[i:i+8]
        out.extend(encrypt_block(block, subkeys))
    return bytes(out)

def decrypt_bytes(ciphertext: bytes, key_hex: str) -> bytes:
    key = int(key_hex, 16)
    subkeys = _generate_subkeys(key)
    out = bytearray()
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        out.extend(decrypt_block(block, subkeys))
    plain_padded = bytes(out)
    return unpad_pkcs7(plain_padded)

# ---------------------
# Simulasi 2 devices
# ---------------------

class Device:
    def __init__(self, name: str):
        self.name = name
        # mapping peer_name -> key hex used for messages FROM self TO peer
        self.out_keys = {}
        # mapping peer_name -> key hex used for messages FROM peer TO self (optional, often same)
        self.in_keys = {}

    def set_out_key(self, peer: str, key_hex: str):
        self.out_keys[peer] = key_hex

    def set_in_key(self, peer: str, key_hex: str):
        self.in_keys[peer] = key_hex

    def send(self, peer: 'Device', plaintext: str):
        key = self.out_keys.get(peer.name)
        if key is None:
            raise ValueError(f"{self.name} has no out key for {peer.name}")
        pt_bytes = plaintext.encode('utf-8')
        ciphertext = encrypt_bytes(pt_bytes, key)
        print(f"[{self.name}] SEND -> {peer.name}")
        print(f"  Plaintext: {plaintext}")
        print(f"  Key used (hex): {key}")
        print(f"  Ciphertext (hex): {ciphertext.hex().upper()}")
        # deliver to peer
        peer.receive(self, ciphertext)

    def receive(self, sender: 'Device', ciphertext: bytes):
        key = self.in_keys.get(sender.name)
        if key is None:
            raise ValueError(f"{self.name} has no in key for {sender.name}")
        print(f"[{self.name}] RECEIVE <- {sender.name}")
        print(f"  Received ciphertext (hex): {ciphertext.hex().upper()}")
        print(f"  Key used to decrypt (hex): {key}")
        try:
            plaintext = decrypt_bytes(ciphertext, key).decode('utf-8')
        except Exception as e:
            plaintext = f"<decryption error: {e}>"
        print(f"  Recovered plaintext: {plaintext}")
        print("-"*60)

# ---------------------
# Demo / main
# ---------------------

def demo_rounds():
    # Example keys (16 hex digits = 64-bit)
    # Key_AB: used by A to encrypt messages to B; B knows this key to decrypt
    # Key_BA: used by B to encrypt messages to A; A knows this key to decrypt
    Key_AB = "133457799BBCDFF1"  # classic DES test key
    Key_BA = "0123456789ABCDEF"  # another 64-bit hex key

    A = Device("DeviceA")
    B = Device("DeviceB")

    # configure keys both sides (both know both keys if desired)
    A.set_out_key("DeviceB", Key_AB)   # A -> B uses Key_AB
    B.set_in_key("DeviceA", Key_AB)    # B can decrypt messages from A with Key_AB

    B.set_out_key("DeviceA", Key_BA)   # B -> A uses Key_BA
    A.set_in_key("DeviceB", Key_BA)    # A can decrypt messages from B with Key_BA

    print("=== Simulasi komunikasi dua device menggunakan DES (ECB, PKCS7) ===\n")

    # A -> B
    A.send(B, "Halo Device B, ini Device A. (1->2)")
    # B -> A
    B.send(A, "Halo Device A, pesan diterima. (2->1)")
    # A -> B again
    A.send(B, "Meneruskan data: angka=42, status=OK. (1->2)")
    # B -> A again
    B.send(A, "Acknowledged. (2->1)")

    print("=== Selesai simulasi ===")

if __name__ == "__main__":
    demo_rounds()
