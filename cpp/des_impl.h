#pragma once
#include <vector>
#include <cstdint>
#include <string>

std::vector<uint8_t> des_encrypt_bytes(const std::vector<uint8_t>& plaintext, const std::string& key_hex);
std::vector<uint8_t> des_decrypt_bytes(const std::vector<uint8_t>& ciphertext, const std::string& key_hex);
