#pragma once

#include <cryptopp/cryptlib.h>   // CryptoPP::Exception
#include <cryptopp/base64.h>
#include <cryptopp/cast.h>
#include <cryptopp/eax.h>
#include <cryptopp/filters.h>
#include <cryptopp/twofish.h>
#include <zlib.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

namespace pka2xml {

// ================================================================
// zlib wrappers
// ================================================================

inline std::string uncompress(const unsigned char *data, int nbytes) {
    if (nbytes < 5) {
        throw std::runtime_error("uncompress: input too short");
    }

    unsigned long len =
        (static_cast<unsigned long>(data[0]) << 24) |
        (static_cast<unsigned long>(data[1]) << 16) |
        (static_cast<unsigned long>(data[2]) << 8)  |
        (static_cast<unsigned long>(data[3]));

    // Sanity check — cap at 256 MB to avoid bad_alloc from garbage data
    if (len == 0 || len > 256u * 1024u * 1024u) {
        std::fprintf(stderr,
            "[warn] uncompress: claimed size = %lu, capping at 256MB\n", len);
        std::fflush(stderr);
        if (len == 0) len = static_cast<unsigned long>(nbytes) * 10;
        if (len > 256u * 1024u * 1024u) len = 256u * 1024u * 1024u;
    }

    std::vector<unsigned char> buf(len);
    unsigned long actual = len;

    int res = ::uncompress(buf.data(), &actual, data + 4, nbytes - 4);

    if (res == Z_BUF_ERROR) {
        // Retry with bigger buffer
        len *= 4;
        buf.resize(len);
        actual = len;
        res = ::uncompress(buf.data(), &actual, data + 4, nbytes - 4);
    }

    if (res != Z_OK) {
        std::fprintf(stderr, "[zlib] uncompress failed: %d\n", res);
        std::fflush(stderr);
        throw res;
    }

    return std::string(reinterpret_cast<const char *>(buf.data()),
                       static_cast<std::size_t>(actual));
}

inline std::string compress(const unsigned char *data, int nbytes) {
    unsigned long len =
        static_cast<unsigned long>(nbytes) + nbytes / 100 + 13;

    std::vector<unsigned char> buf(len + 4);

    int res = ::compress2(buf.data() + 4, &len,
                          data, static_cast<unsigned long>(nbytes),
                          Z_DEFAULT_COMPRESSION);
    if (res != Z_OK) {
        throw res;
    }

    buf.resize(static_cast<std::size_t>(len) + 4);

    buf[0] = static_cast<unsigned char>((nbytes >> 24) & 0xFF);
    buf[1] = static_cast<unsigned char>((nbytes >> 16) & 0xFF);
    buf[2] = static_cast<unsigned char>((nbytes >> 8)  & 0xFF);
    buf[3] = static_cast<unsigned char>((nbytes)       & 0xFF);

    return std::string(reinterpret_cast<const char *>(buf.data()),
                       buf.size());
}

// ================================================================
// 4-stage decrypt
//   deobfuscate → Twofish-EAX decrypt → deobfuscate → zlib decompress
// ================================================================

template <typename Algorithm>
inline std::string decrypt(const std::string &input,
                           const std::array<unsigned char, 16> &key,
                           const std::array<unsigned char, 16> &iv) {
    typename CryptoPP::EAX<Algorithm>::Decryption d;
    d.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    const int length = static_cast<int>(input.size());
    std::string processed(static_cast<std::size_t>(length), '\0');
    std::string output;

    // Stage 1 — reverse + xor deobfuscation
    for (int i = 0; i < length; i++) {
        // length + ~i  ==  length - i - 1
        processed[i] = input[length - 1 - i] ^
                       static_cast<char>(static_cast<unsigned char>(
                           (length - (long long)i * length) & 0xFF));
    }

    // Stage 2 — authenticated decryption
    CryptoPP::StringSource ss(
        processed, true,
        new CryptoPP::AuthenticatedDecryptionFilter(
            d, new CryptoPP::StringSink(output)));

    // Stage 3 — xor deobfuscation
    const int osize = static_cast<int>(output.size());
    for (int i = 0; i < osize; i++) {
        output[i] = output[i] ^ static_cast<char>((osize - i) & 0xFF);
    }

    // Stage 4 — zlib decompress
    return uncompress(
        reinterpret_cast<const unsigned char *>(output.data()), osize);
}

/// 2-stage variant (deobfuscate → decrypt only), used by logs / nets.
template <typename Algorithm>
inline std::string decrypt2(const std::string &input,
                            const std::array<unsigned char, 16> &key,
                            const std::array<unsigned char, 16> &iv) {
    typename CryptoPP::EAX<Algorithm>::Decryption d;
    d.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    const int length = static_cast<int>(input.size());
    std::string processed(static_cast<std::size_t>(length), '\0');
    std::string output;

    for (int i = 0; i < length; i++) {
        processed[i] = input[length - 1 - i] ^
                       static_cast<char>(static_cast<unsigned char>(
                           (length - (long long)i * length) & 0xFF));
    }

    CryptoPP::StringSource ss(
        processed, true,
        new CryptoPP::AuthenticatedDecryptionFilter(
            d, new CryptoPP::StringSink(output)));

    return output;
}

// ================================================================
// 4-stage encrypt  (compress → obfuscate → encrypt → obfuscate)
// ================================================================

template <typename Algorithm>
inline std::string encrypt(const std::string &input,
                           const std::array<unsigned char, 16> &key,
                           const std::array<unsigned char, 16> &iv) {
    typename CryptoPP::EAX<Algorithm>::Encryption e;
    e.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    // Stage 1 — compress
    std::string compressed = compress(
        reinterpret_cast<const unsigned char *>(input.data()),
        static_cast<int>(input.size()));

    // Stage 2 — obfuscate
    const int csize = static_cast<int>(compressed.size());
    for (int i = 0; i < csize; i++) {
        compressed[i] = compressed[i] ^ static_cast<char>((csize - i) & 0xFF);
    }

    // Stage 3 — authenticated encryption
    std::string encrypted;
    CryptoPP::StringSource ss(
        compressed, true,
        new CryptoPP::AuthenticatedEncryptionFilter(
            e, new CryptoPP::StringSink(encrypted)));

    // Stage 4 — obfuscate
    const int length = static_cast<int>(encrypted.size());
    std::string output(static_cast<std::size_t>(length), '\0');
    for (int i = 0; i < length; i++) {
        output[length - 1 - i] = encrypted[i] ^
            static_cast<char>(static_cast<unsigned char>(
                (length - (long long)i * length) & 0xFF));
    }

    return output;
}

/// 2-stage variant (encrypt → obfuscate only), used by nets.
template <typename Algorithm>
inline std::string encrypt2(const std::string &input,
                            const std::array<unsigned char, 16> &key,
                            const std::array<unsigned char, 16> &iv) {
    typename CryptoPP::EAX<Algorithm>::Encryption e;
    e.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    std::string encrypted;
    CryptoPP::StringSource ss(
        input, true,
        new CryptoPP::AuthenticatedEncryptionFilter(
            e, new CryptoPP::StringSink(encrypted)));

    const int length = static_cast<int>(encrypted.size());
    std::string output(static_cast<std::size_t>(length), '\0');
    for (int i = 0; i < length; i++) {
        output[length - 1 - i] = encrypted[i] ^
            static_cast<char>(static_cast<unsigned char>(
                (length - (long long)i * length) & 0xFF));
    }

    return output;
}

// ================================================================
// Public API
// ================================================================

inline std::string decrypt_pka(const std::string &input) {
    static const std::array<unsigned char, 16> key{
        137,137,137,137,137,137,137,137,
        137,137,137,137,137,137,137,137};
    static const std::array<unsigned char, 16> iv{
        16,16,16,16,16,16,16,16,
        16,16,16,16,16,16,16,16};
    return decrypt<CryptoPP::Twofish>(input, key, iv);
}

inline std::string encrypt_pka(const std::string &input) {
    static const std::array<unsigned char, 16> key{
        137,137,137,137,137,137,137,137,
        137,137,137,137,137,137,137,137};
    static const std::array<unsigned char, 16> iv{
        16,16,16,16,16,16,16,16,
        16,16,16,16,16,16,16,16};
    return encrypt<CryptoPP::Twofish>(input, key, iv);
}

inline std::string decrypt_old(std::string input) {
    const int sz = static_cast<int>(input.size());
    for (int i = 0; i < sz; i++) {
        input[i] = input[i] ^ static_cast<char>((sz - i) & 0xFF);
    }
    return uncompress(
        reinterpret_cast<const unsigned char *>(input.data()), sz);
}

inline std::string decrypt_logs(const std::string &input) {
    static const std::array<unsigned char, 16> key{
        186,186,186,186,186,186,186,186,
        186,186,186,186,186,186,186,186};
    static const std::array<unsigned char, 16> iv{
        190,190,190,190,190,190,190,190,
        190,190,190,190,190,190,190,190};

    std::string decoded;
    CryptoPP::StringSource ss(
        input, true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(decoded)));

    return decrypt2<CryptoPP::Twofish>(decoded, key, iv);
}

inline std::string decrypt_nets(const std::string &input) {
    static const std::array<unsigned char, 16> key{
        186,186,186,186,186,186,186,186,
        186,186,186,186,186,186,186,186};
    static const std::array<unsigned char, 16> iv{
        190,190,190,190,190,190,190,190,
        190,190,190,190,190,190,190,190};
    return decrypt2<CryptoPP::Twofish>(input, key, iv);
}

inline std::string encrypt_nets(const std::string &input) {
    static const std::array<unsigned char, 16> key{
        186,186,186,186,186,186,186,186,
        186,186,186,186,186,186,186,186};
    static const std::array<unsigned char, 16> iv{
        190,190,190,190,190,190,190,190,
        190,190,190,190,190,190,190,190};
    return encrypt2<CryptoPP::Twofish>(input, key, iv);
}

/// Detect pre-PT5 format (xor + zlib only, no Twofish).
inline bool is_old_pt(const std::string &str) {
    if (str.size() < 6) return false;
    const int sz = static_cast<int>(str.size());
    unsigned char b4 = static_cast<unsigned char>(str[4]) ^
                       static_cast<unsigned char>((sz - 4) & 0xFF);
    unsigned char b5 = static_cast<unsigned char>(str[5]) ^
                       static_cast<unsigned char>((sz - 5) & 0xFF);
    // zlib header bytes: 0x78 (CMF), 0x9C (FLG for default compression)
    return (b4 == 0x78) || (b5 == 0x9C);
}

/// Patch version string so any PT version can open the file.
inline std::string fix(std::string input) {
    std::string clear =
        is_old_pt(input) ? decrypt_old(input) : decrypt_pka(input);

    clear = std::regex_replace(
        clear,
        std::regex(R"(<VERSION>\d\.\d\.\d\.\d{4}</VERSION>)"),
        "<VERSION>6.0.1.0000</VERSION>");

    return encrypt_pka(clear);
}

}  // namespace pka2xml