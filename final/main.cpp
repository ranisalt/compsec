#include <cassert>
#include <iostream>

#include "Keccak.h"

std::string hash_str(const std::string& hash)
{
    std::stringstream ss;
    ss << std::hex;
    for (const auto& ch: hash) {
        ss << (unsigned)ch % 256;
    }
    return ss.str();
}

int main()
{
    auto sha224hash = std::string{"\x6b\x4e\x03\x42"
                                  "\x36\x67\xdb\xb7"
                                  "\x3b\x6e\x15\x45"
                                  "\x4f\x0e\xb1\xab"
                                  "\xd4\x59\x7f\x9a"
                                  "\x1b\x07\x8e\x3f"
                                  "\x5b\x5a\x6b\xc7", 28u};
    assert(SHA3_224::hash("") == sha224hash);
    std::cout << "SHA3_224(\"\") = " << hash_str(sha224hash) << std::endl;

    auto sha256hash = std::string{"\xa7\xff\xc6\xf8"
                                  "\xbf\x1e\xd7\x66"
                                  "\x51\xc1\x47\x56"
                                  "\xa0\x61\xd6\x62"
                                  "\xf5\x80\xff\x4d"
                                  "\xe4\x3b\x49\xfa"
                                  "\x82\xd8\x0a\x4b"
                                  "\x80\xf8\x43\x4a", 32u};
    assert(SHA3_256::hash("") == sha256hash);
    std::cout << "SHA3_256(\"\") = " << hash_str(sha256hash) << std::endl;

    auto sha384hash = std::string{"\x0c\x63\xa7\x5b"
                                  "\x84\x5e\x4f\x7d"
                                  "\x01\x10\x7d\x85"
                                  "\x2e\x4c\x24\x85"
                                  "\xc5\x1a\x50\xaa"
                                  "\xaa\x94\xfc\x61"
                                  "\x99\x5e\x71\xbb"
                                  "\xee\x98\x3a\x2a"
                                  "\xc3\x71\x38\x31"
                                  "\x26\x4a\xdb\x47"
                                  "\xfb\x6b\xd1\xe0"
                                  "\x58\xd5\xf0\x04", 48u};
    assert(SHA3_384::hash("") == sha384hash);
    std::cout << "SHA3_384(\"\") = " << hash_str(sha384hash) << std::endl;

    auto sha512hash = std::string{"\xa6\x9f\x73\xcc"
                                  "\xa2\x3a\x9a\xc5"
                                  "\xc8\xb5\x67\xdc"
                                  "\x18\x5a\x75\x6e"
                                  "\x97\xc9\x82\x16"
                                  "\x4f\xe2\x58\x59"
                                  "\xe0\xd1\xdc\xc1"
                                  "\x47\x5c\x80\xa6"
                                  "\x15\xb2\x12\x3a"
                                  "\xf1\xf5\xf9\x4c"
                                  "\x11\xe3\xe9\x40"
                                  "\x2c\x3a\xc5\x58"
                                  "\xf5\x00\x19\x9d"
                                  "\x95\xb6\xd3\xe3"
                                  "\x01\x75\x85\x86"
                                  "\x28\x1d\xcd\x26", 64u};
    assert(SHA3_512::hash("") == sha512hash);
    std::cout << "SHA3_512(\"\") = " << hash_str(sha512hash) << std::endl;

    std::string  shake128hash[] = {
            std::string{"\x7f\x9c\x2b\xa4\xe8\x8f\x82\x7d\x61\x60\x45\x50\x76\x05\x85\x3e", 16u},
            std::string{"\x7f\x9c\x2b\xa4\xe8\x8f\x82\x7d\x61\x60\x45\x50\x76\x05\x85\x3e", 16u},
    };
    auto shake128 = SHAKE_128{};
    shake128.finalize();
    assert(shake128.digest(16u) == shake128hash[0]);
    assert(shake128.digest(16u) != shake128hash[1]);

    std::string shake256hash[] = {
            std::string{"\x46\xb9\xdd\x2b\x0b\xa8\x8d\x13\x23\x3b\x3f\xeb\x74\x3e\xeb\x24", 16u},
            std::string{"\x3f\xcd\x52\xea\x62\xb8\x1b\x82\xb5\x0c\x27\x64\x6e\xd5\x76\x2f", 16u},
    };
    auto shake256 = SHAKE_256{};
    shake256.finalize();
    assert(shake256.digest(16u) == shake256hash[0]);
    assert(shake256.digest(16u) == shake256hash[1]);

    return 0;
}
