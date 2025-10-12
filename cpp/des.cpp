// des.cpp - simple DES implementation (ECB) - educational only
#include <cstdint>
#include <vector>
#include <array>
#include <stdexcept>
#include <cstring>

using u8 = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

static const int IP[64] = {
58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,
64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
};
static const int FP[64] = {
40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,
37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
};
static const int E[48] = {
32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1
};
static const int P[32] = {
16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
};
static const int PC1[56] = {
57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,
59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,
62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4
};
static const int PC2[48] = {
14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32
};
static const int SHIFTS[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
static const int S_BOX[8][4][16] = {
{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
{{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
{{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
{{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
{{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
{{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8}},
{{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
{{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
};

// helper: get bit (1-based indexing in tables)
inline int get_bit(u64 v, int pos) {
    return (v >> (64 - pos)) & 1ULL;
}
inline u64 set_bit(u64 v, int pos, int bit) {
    if (bit) v |= (1ULL << (64-pos));
    else v &= ~(1ULL << (64-pos));
    return v;
}

// convert 8 bytes to 64-bit value (MSB first)
u64 bytes_to_u64(const u8 *b) {
    u64 v = 0;
    for (int i=0;i<8;i++) v = (v<<8) | b[i];
    return v;
}
void u64_to_bytes(u64 v, u8 *b) {
    for (int i=7;i>=0;i--) { b[i] = v & 0xFF; v >>= 8; }
}

std::array<u64,16> generate_subkeys(u64 key) {
    // apply PC1 to 64-bit key -> 56 bits in a u64 container (left aligned)
    u8 bits56[56];
    for (int i=0;i<56;i++) bits56[i] = get_bit(key, PC1[i]);
    // split into C and D (28 bits each)
    u32 C=0, D=0;
    for (int i=0;i<28;i++) { C = (C<<1) | bits56[i]; D = (D<<1) | bits56[28+i]; }
    std::array<u64,16> subkeys;
    for (int round=0; round<16; ++round) {
        int s = SHIFTS[round];
        C = ((C << s) & 0x0FFFFFFF) | (C >> (28 - s));
        D = ((D << s) & 0x0FFFFFFF) | (D >> (28 - s));
        // combine C and D into 56 bits array
        u8 cd[56];
        for (int i=27;i>=0;i--) { cd[27-i] = (C >> i) & 1; cd[55-(27-i)] = (D >> i) & 1; }
        // apply PC2 to get 48-bit subkey
        u64 sub=0;
        for (int i=0;i<48;i++) { sub = (sub<<1) | cd[PC2[i]-1]; }
        subkeys[round] = sub;
    }
    return subkeys;
}

u32 feistel(u32 r, u64 subkey) {
    // expand r (32 bits) to 48 bits then xor with subkey, apply S-boxes, then P
    u8 rbits[32];
    for (int i=0;i<32;i++) rbits[i] = (r >> (31 - i)) & 1;
    u8 e_bits[48];
    for (int i=0;i<48;i++) e_bits[i] = rbits[E[i]-1];
    // to int
    u64 e_val = 0;
    for (int i=0;i<48;i++) e_val = (e_val<<1) | e_bits[i];
    u64 x = e_val ^ subkey;
    u8 s_out_bits[32]; int out_pos=0;
    for (int i=0;i<8;i++) {
        int six = (x >> (42 - 6*i)) & 0x3F;
        int row = ((six & 0x20) >> 4) | (six & 1);
        int col = (six >> 1) & 0xF;
        int s = S_BOX[i][row][col];
        for (int b=3;b>=0;b--) { s_out_bits[out_pos++] = (s>>b)&1; }
    }
    u32 pval=0;
    for (int i=0;i<32;i++) { pval = (pval<<1) | s_out_bits[P[i]-1]; }
    return pval;
}

void permute_block(const u8 *in, u8 *out, const int *table, int n) {
    // in: 8 bytes -> produce n bits in out (packed as bytes)
    u8 inbits[64];
    for (int i=0;i<64;i++) inbits[i] = (in[i/8] >> (7-(i%8))) & 1;
    u8 outbits[64]; memset(outbits,0,sizeof(outbits));
    for (int i=0;i<n;i++) outbits[i] = inbits[table[i]-1];
    // pack first 64 bits back to bytes (we use 64 always)
    for (int i=0;i<8;i++) {
        out[i]=0;
        for (int j=0;j<8;j++) out[i] = (out[i]<<1) | outbits[i*8+j];
    }
}

void encrypt_block(const u8 in[8], u8 out[8], const std::array<u64,16>& subkeys) {
    u8 ip_out[8]; permute_block(in, ip_out, IP, 64);
    u32 L=0,R=0;
    for (int i=0;i<4;i++) { L = (L<<8) | ip_out[i]; }
    for (int i=4;i<8;i++) { R = (R<<8) | ip_out[i]; }
    for (int i=0;i<16;i++) {
        u32 f = feistel(R, subkeys[i]);
        u32 tmp = L ^ f;
        L = R; R = tmp;
    }
    u8 pre[8];
    pre[0] = (R>>24)&0xFF; pre[1]=(R>>16)&0xFF; pre[2]=(R>>8)&0xFF; pre[3]=R&0xFF;
    pre[4] = (L>>24)&0xFF; pre[5]=(L>>16)&0xFF; pre[6]=(L>>8)&0xFF; pre[7]=L&0xFF;
    permute_block(pre, out, FP, 64);
}

void decrypt_block(const u8 in[8], u8 out[8], const std::array<u64,16>& subkeys) {
    std::array<u64,16> rev = subkeys;
    std::reverse(rev.begin(), rev.end());
    encrypt_block(in, out, rev);
}

// PKCS7 padding helpers
std::vector<u8> pad_pkcs7(const std::vector<u8>& data) {
    size_t pad_len = 8 - (data.size() % 8);
    if (pad_len==0) pad_len=8;
    std::vector<u8> out = data;
    out.insert(out.end(), pad_len, (u8)pad_len);
    return out;
}
std::vector<u8> unpad_pkcs7(const std::vector<u8>& data) {
    if (data.empty()) return data;
    u8 pad = data.back();
    if (pad<1 || pad>8) throw std::runtime_error("Invalid padding");
    for (size_t i=data.size()-pad;i<data.size();++i) if (data[i]!=pad) throw std::runtime_error("Invalid padding");
    return std::vector<u8>(data.begin(), data.end()-pad);
}


#include <string>
#include <algorithm>
#include <stdexcept>

// helper to convert hex key string to u64
static uint64_t hex_to_u64(const std::string &hex) {
    uint64_t v=0;
    for (char c:hex) {
        v <<= 4;
        if (c>='0' && c<='9') v += c-'0';
        else if (c>='a' && c<='f') v += 10 + c-'a';
        else if (c>='A' && c<='F') v += 10 + c-'A';
        else throw std::runtime_error("Invalid hex in key");
    }
    return v;
}

std::vector<uint8_t> des_encrypt_bytes(const std::vector<uint8_t>& plaintext, const std::string& key_hex) {
    uint64_t key = hex_to_u64(key_hex);
    auto subkeys = generate_subkeys(key);
    auto padded = pad_pkcs7(plaintext);
    std::vector<uint8_t> out;
    out.resize(padded.size());
    for (size_t i=0;i<padded.size(); i+=8) {
        encrypt_block(&padded[i], &out[i], subkeys);
    }
    return out;
}

std::vector<uint8_t> des_decrypt_bytes(const std::vector<uint8_t>& ciphertext, const std::string& key_hex) {
    uint64_t key = hex_to_u64(key_hex);
    auto subkeys = generate_subkeys(key);
    if (ciphertext.size() % 8 != 0) throw std::runtime_error("Invalid ciphertext length");
    std::vector<uint8_t> out;
    out.resize(ciphertext.size());
    for (size_t i=0;i<ciphertext.size(); i+=8) {
        decrypt_block(&ciphertext[i], &out[i], subkeys);
    }
    return unpad_pkcs7(out);
}
