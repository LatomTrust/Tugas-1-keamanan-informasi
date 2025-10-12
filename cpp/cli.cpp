// cli.cpp - minimal wrapper to encrypt/decrypt files using des.cpp
#include <fstream>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include "des_impl.h" // forward declarations

int hex_to_u64(const std::string &hex, uint64_t &out) {
    std::stringstream ss;
    ss << std::hex << hex;
    ss >> out;
    return 0;
}

std::vector<uint8_t> read_file(const std::string &path) {
    std::ifstream ifs(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
}
void write_file(const std::string &path, const std::vector<uint8_t>& data) {
    std::ofstream ofs(path, std::ios::binary);
    ofs.write((const char*)data.data(), data.size());
}

int main(int argc, char** argv) {
    if (argc<5) {
        std::cerr<<"Usage: des_cli <encrypt|decrypt> <16hexkey> <infile> <outfile>\n";
        return 1;
    }
    std::string mode=argv[1], key=argv[2], in=argv[3], out=argv[4];
    uint64_t k=0;
    std::stringstream ss; ss<<std::hex<<key; ss>>k;
    auto dat = read_file(in);
    try {
        std::vector<uint8_t> outd;
        if (mode=="encrypt") outd = des_encrypt_bytes(dat, key);
        else outd = des_decrypt_bytes(dat, key);
        write_file(out, outd);
        std::cout<<"Done: "<<mode<<" -> "<<out<<"\n";
    } catch (std::exception &e) {
        std::cerr<<"Error: "<<e.what()<<"\n"; return 2;
    }
    return 0;
}
