#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ripemd.h>
#include <openssl/obj_mac.h>
#include "vendor/base58/base58.hpp"

#include <array>
#include <vector>
#include <utility>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <optional>

using UC_VECTOR = std::vector<uint8_t>;

std::optional<EC_KEY*> create_ec_key(const UC_VECTOR& privateKey) {
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        std::cerr << "Ошибка при создании EC ключа." << std::endl;
        return std::nullopt;
    }

    BIGNUM* priv_key_bn = BN_bin2bn(privateKey.data(), privateKey.size(), nullptr);
    if (!priv_key_bn || !EC_KEY_set_private_key(ec_key, priv_key_bn)) {
        std::cerr << "Ошибка при установке приватного ключа." << std::endl;
        BN_free(priv_key_bn);
        EC_KEY_free(ec_key);
        return std::nullopt;
    }

    if (!EC_KEY_generate_key(ec_key)) {
        std::cerr << "Ошибка при генерации ключа." << std::endl;
        BN_free(priv_key_bn);
        EC_KEY_free(ec_key);
        return std::nullopt;
    }

    BN_free(priv_key_bn);
    return ec_key;
}

std::pair<std::string, UC_VECTOR> generate_public_key(const UC_VECTOR& privateKey, bool isCompressed) {
    auto ec_key = create_ec_key(privateKey);
    if (!ec_key) {
        return { "", UC_VECTOR() };
    }

    const EC_POINT* pub_key = EC_KEY_get0_public_key(*ec_key);
    if (!pub_key) {
        std::cerr << "Ошибка при получении публичного ключа." << std::endl;
        EC_KEY_free(*ec_key);
        return { "", UC_VECTOR() };
    }

    char* pub_key_hex = EC_POINT_point2hex(EC_KEY_get0_group(*ec_key), pub_key,
                                             isCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED, nullptr);
    std::string publicKey(pub_key_hex ? pub_key_hex : "");
    OPENSSL_free(pub_key_hex);
    EC_KEY_free(*ec_key);

    return { publicKey, UC_VECTOR(publicKey.begin(), publicKey.end()) };
}

std::pair<std::string, UC_VECTOR> sha256(const std::string& str) {
    UC_VECTOR data(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(str.data()), str.size(), data.data());

    std::ostringstream oss;
    for (const auto& c : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }

    return { oss.str(), data };
}

UC_VECTOR double_sha256(const UC_VECTOR& data) {
    UC_VECTOR hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    SHA256(hash.data(), hash.size(), hash.data());
    return hash;
}

std::pair<std::string, UC_VECTOR> ripemd160(const UC_VECTOR& data) {
    UC_VECTOR ripemd(RIPEMD160_DIGEST_LENGTH);
    RIPEMD160(data.data(), data.size(), ripemd.data());

    std::ostringstream oss;
    for (const auto& c : ripemd) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }

    return { oss.str(), ripemd };
}

std::string create_wif(const UC_VECTOR& privateKey, bool isCompressed) {
    UC_VECTOR extendedKey{ 0x80 };
    extendedKey.insert(extendedKey.end(), privateKey.begin(), privateKey.end());
    if (isCompressed) {
        extendedKey.push_back(0x01);
    }

    const UC_VECTOR checksum = double_sha256(extendedKey);
    extendedKey.insert(extendedKey.end(), checksum.begin(), checksum.begin() + 4);

    return encodeBase58(extendedKey);
}

std::pair<std::string, UC_VECTOR>  create_p2pkh_address(const UC_VECTOR& publicKeyBytes) {
    const auto [sha256Hex, sha256Bytes] = sha256(std::string(publicKeyBytes.begin(), publicKeyBytes.end()));
    const auto [ripemdHex, pkhBytes] = ripemd160(sha256Bytes);

    UC_VECTOR versionedPKH{ 0x00 };
    versionedPKH.insert(versionedPKH.end(), pkhBytes.begin(), pkhBytes.end());

    const UC_VECTOR checksum = double_sha256(versionedPKH);
    versionedPKH.insert(versionedPKH.end(), checksum.begin(), checksum.begin() + 4); 

    return { encodeBase58(versionedPKH), versionedPKH };
}

std::string create_p2sh_address(const UC_VECTOR& script) {
    const auto [sha256Hex, sha256Bytes] = sha256(std::string(script.begin(), script.end()));
    const auto [ripemdHex, pkhBytes] = ripemd160(sha256Bytes);

    UC_VECTOR versionedPKH{ 0x05 };
    versionedPKH.insert(versionedPKH.end(), pkhBytes.begin(), pkhBytes.end());

    const UC_VECTOR checksum = double_sha256(versionedPKH);
    versionedPKH.insert(versionedPKH.end(), checksum.begin(), checksum.begin() + 4);

    return encodeBase58(versionedPKH);
}

int main(int argc, char** argv) {
    const std::string input = "bitcoin is awesome";
    std::cout << "Source: " << input << std::endl;

    const auto& [sha256Hex, sha256Bytes] = sha256(input);
    std::cout << "HEX: " << sha256Hex << std::endl;

    std::cout << "WIF(c): " << create_wif(sha256Bytes, true) << std::endl;
    std::cout << "WIF(u): " << create_wif(sha256Bytes, false) << std::endl;

    const auto& [publicKeyStr_c, publicKeyBytes_c] = generate_public_key(sha256Bytes, true);
    const auto& [publicKeyStr_u, publicKeyBytes_u] = generate_public_key(sha256Bytes, false);

    const auto& [p2pkh_u_hex, p2pkh_u_bytes] = create_p2pkh_address(publicKeyBytes_u);
    std::cout << "P2PKH(u): " << p2pkh_u_hex << std::endl;

    const auto& [p2pkh_c_hex, p2pkh_c_bytes] = create_p2pkh_address(publicKeyBytes_c);
    std::cout << "P2PKH(c): " << p2pkh_c_hex << std::endl;

    UC_VECTOR script = { 0x76, 0xa9, 0x14 };
    script.insert(script.end(), p2pkh_c_bytes.begin(), p2pkh_c_bytes.end());
    script.insert(script.end(), { 0x88, 0xac });

    std::string p2shAddress = create_p2sh_address(script);
    std::cout << "P2SH(c): " << p2shAddress << std::endl;

    return 0;
}
