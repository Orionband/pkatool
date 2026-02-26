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
#include <fstream>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

namespace pkatool {

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

// ================================================================
// Password removal
// ================================================================

inline std::string remove_password(const std::string& xml) {
    if (xml.empty()) return xml;
    
    std::fprintf(stderr, "[info] removing password from XML (%zu bytes)\n", xml.size());
    std::fflush(stderr);
    
    std::string result = xml;
    
    // Clear PASS attribute values: PASS="anything" -> PASS=""
    try {
        result = std::regex_replace(result, 
            std::regex(R"(PASS="[^"]*")"), 
            "PASS=\"\"");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[warn] regex error clearing PASS: %s\n", e.what());
    }
    
    // Remove VALUE attribute from ACTIVITY tags
    // Match ACTIVITY tag and capture parts before/after VALUE
    try {
        result = std::regex_replace(result,
            std::regex(R"((<ACTIVITY\s[^>]*)\sVALUE="[^"]*"([^>]*>))"),
            "$1$2");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[warn] regex error removing VALUE: %s\n", e.what());
    }
    
    std::fprintf(stderr, "[info] password removal complete\n");
    std::fflush(stderr);
    
    return result;
}

// ================================================================
// Unlock activity
// ================================================================

inline std::string unlock_activity(const std::string& xml) {
    if (xml.empty()) return xml;
    
    std::fprintf(stderr, "[info] unlocking activity in XML (%zu bytes)\n", xml.size());
    std::fflush(stderr);
    
    std::string result = xml;
    
    // Change on="yes" to on="no" in NODE tags
    try {
        result = std::regex_replace(result,
            std::regex(R"((<NODE\s[^>]*)on="yes"([^>]*>))"),
            "$1on=\"no\"$2");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[warn] regex error unlocking nodes: %s\n", e.what());
    }
    
    // Also handle single quotes
    try {
        result = std::regex_replace(result,
            std::regex(R"((<NODE\s[^>]*)on='yes'([^>]*>))"),
            "$1on='no'$2");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[warn] regex error unlocking nodes (single quote): %s\n", e.what());
    }
    
    std::fprintf(stderr, "[info] unlock complete\n");
    std::fflush(stderr);
    
    return result;
}

// ================================================================
// Extract networks - returns vector of XML strings
// ================================================================

inline std::vector<std::string> extract_networks(const std::string& xml) {
    std::vector<std::string> networks;
    
    if (xml.empty()) {
        std::fprintf(stderr, "[warn] extract_networks: empty input\n");
        return networks;
    }
    
    std::fprintf(stderr, "[info] searching for PACKETTRACER5 sections in %zu bytes\n", 
                 xml.size());
    std::fflush(stderr);
    
    const char* start_tag = "<PACKETTRACER5>";
    const char* end_tag = "</PACKETTRACER5>";
    const size_t start_tag_len = 15;
    const size_t end_tag_len = 16;
    
    size_t pos = 0;
    int section_num = 0;
    
    while (pos < xml.size()) {
        size_t start = xml.find(start_tag, pos);
        if (start == std::string::npos) {
            break;
        }
        
        size_t end = xml.find(end_tag, start + start_tag_len);
        if (end == std::string::npos) {
            std::fprintf(stderr, "[warn] no matching end tag for section at %zu\n", start);
            break;
        }
        
        size_t section_end = end + end_tag_len;
        size_t section_len = section_end - start;
        
        std::fprintf(stderr, "[info] found section %d: offset %zu, length %zu\n",
                     section_num, start, section_len);
        std::fflush(stderr);
        
        networks.push_back(xml.substr(start, section_len));
        section_num++;
        
        pos = section_end;
    }
    
    std::fprintf(stderr, "[info] extracted %zu total sections\n", networks.size());
    std::fflush(stderr);
    
    return networks;
}

// ================================================================
// High-level wrapper functions
// ================================================================

inline std::string remove_password_from_file(const std::string& input) {
    std::fprintf(stderr, "[info] decrypting for password removal...\n");
    std::fflush(stderr);
    
    std::string xml = is_old_pt(input) ? decrypt_old(input) : decrypt_pka(input);
    
    std::fprintf(stderr, "[info] decrypted, size = %zu\n", xml.size());
    std::fflush(stderr);
    
    xml = remove_password(xml);
    
    std::fprintf(stderr, "[info] re-encrypting...\n");
    std::fflush(stderr);
    
    return encrypt_pka(xml);
}

inline std::string unlock_file(const std::string& input) {
    std::fprintf(stderr, "[info] decrypting for unlock...\n");
    std::fflush(stderr);
    
    std::string xml = is_old_pt(input) ? decrypt_old(input) : decrypt_pka(input);
    
    std::fprintf(stderr, "[info] decrypted, size = %zu\n", xml.size());
    std::fflush(stderr);
    
    xml = unlock_activity(xml);
    
    std::fprintf(stderr, "[info] re-encrypting...\n");
    std::fflush(stderr);
    
    return encrypt_pka(xml);
}

inline void extract_and_save_networks(const std::string& input, const char* base_name) {
    std::fprintf(stderr, "[info] decrypting for network extraction...\n");
    std::fflush(stderr);
    
    std::string xml;
    if (is_old_pt(input)) {
        xml = decrypt_old(input);
    } else {
        xml = decrypt_pka(input);
    }
    
    std::fprintf(stderr, "[info] decrypted, xml size = %zu\n", xml.size());
    std::fflush(stderr);
    
    std::vector<std::string> networks = extract_networks(xml);
    
    std::fprintf(stderr, "[info] starting to save %zu networks...\n", networks.size());
    std::fflush(stderr);
    
    xml.clear();
    
    const char* names[3] = {"current", "initial", "answer"};
    
    for (size_t i = 0; i < networks.size() && i < 3; i++) {
        std::fprintf(stderr, "[info] processing network %zu, size = %zu bytes\n", 
                     i, networks[i].size());
        std::fflush(stderr);
        
        if (networks[i].empty()) {
            std::fprintf(stderr, "[info] network %zu is empty, skipping\n", i);
            continue;
        }
        
        std::string filename;
        filename.append(base_name);
        filename.append("_");
        filename.append(names[i]);
        filename.append(".pkt");
        
        std::fprintf(stderr, "[info] encrypting network %zu...\n", i);
        std::fflush(stderr);
        
        std::string encrypted = encrypt_pka(networks[i]);
        
        std::fprintf(stderr, "[info] encrypted size = %zu, writing to %s\n", 
                     encrypted.size(), filename.c_str());
        std::fflush(stderr);
        
        // Write file using C FILE* instead of C++ ofstream
        FILE* f = fopen(filename.c_str(), "wb");
        if (!f) {
            std::fprintf(stderr, "[error] cannot open output file: %s\n", filename.c_str());
            continue;
        }
        
        size_t written = fwrite(encrypted.data(), 1, encrypted.size(), f);
        fclose(f);
        
        if (written != encrypted.size()) {
            std::fprintf(stderr, "[error] write failed: %s\n", filename.c_str());
        } else {
            std::fprintf(stderr, "[info] wrote %s successfully\n", filename.c_str());
        }
    }
    
    std::fprintf(stderr, "[info] network extraction complete\n");
    std::fflush(stderr);
}
inline std::string reset_activity(const std::string& xml) {
    if (xml.empty()) return xml;
    
    std::fprintf(stderr, "[info] resetting activity in XML (%zu bytes)\n", xml.size());
    std::fflush(stderr);
    
    std::string result = xml;
    
    // Step 1: Replace first PACKETTRACER5 section with second (initial)
    const char* start_tag = "<PACKETTRACER5>";
    const char* end_tag = "</PACKETTRACER5>";
    const size_t start_tag_len = 15;
    const size_t end_tag_len = 16;
    
    // Find first section (current)
    size_t first_start = result.find(start_tag);
    if (first_start == std::string::npos) {
        std::fprintf(stderr, "[warn] no PACKETTRACER5 section found\n");
        return result;
    }
    
    size_t first_end = result.find(end_tag, first_start + start_tag_len);
    if (first_end == std::string::npos) {
        std::fprintf(stderr, "[warn] no closing tag for first PACKETTRACER5\n");
        return result;
    }
    first_end += end_tag_len;
    
    // Find second section (initial)
    size_t second_start = result.find(start_tag, first_end);
    if (second_start == std::string::npos) {
        std::fprintf(stderr, "[warn] no second PACKETTRACER5 section found (no initial network)\n");
        return result;
    }
    
    size_t second_end = result.find(end_tag, second_start + start_tag_len);
    if (second_end == std::string::npos) {
        std::fprintf(stderr, "[warn] no closing tag for second PACKETTRACER5\n");
        return result;
    }
    second_end += end_tag_len;
    
    // Extract second section (initial)
    std::string initial_section = result.substr(second_start, second_end - second_start);
    
    std::fprintf(stderr, "[info] replacing current network with initial network\n");
    std::fflush(stderr);
    
    // Replace first section with second
    result = result.substr(0, first_start) + initial_section + result.substr(first_end);
    
    // Step 2: Fix timer values in ACTIVITY tag
    size_t activity_pos = result.find("<ACTIVITY ");
    if (activity_pos == std::string::npos) {
        std::fprintf(stderr, "[info] no ACTIVITY tag found, skipping timer reset\n");
        return result;
    }
    
    size_t activity_end = result.find(">", activity_pos);
    if (activity_end == std::string::npos) {
        std::fprintf(stderr, "[warn] malformed ACTIVITY tag\n");
        return result;
    }
    
    std::string activity_tag = result.substr(activity_pos, activity_end - activity_pos + 1);
    std::string new_activity_tag = activity_tag;
    
    // Check TIMERTYPE
    if (activity_tag.find("TIMERTYPE=\"1\"") != std::string::npos) {
        std::fprintf(stderr, "[info] TIMERTYPE=1 detected, resetting countdown timer\n");
        std::fflush(stderr);
        
        // Get COUNTDOWNMS value
        size_t cdms_pos = activity_tag.find("COUNTDOWNMS=\"");
        if (cdms_pos != std::string::npos) {
            size_t cdms_start = cdms_pos + 13;
            size_t cdms_end = activity_tag.find("\"", cdms_start);
            if (cdms_end != std::string::npos) {
                std::string countdownms = activity_tag.substr(cdms_start, cdms_end - cdms_start);
                
                std::fprintf(stderr, "[info] resetting COUNTDOWNLEFT \n");
                std::fflush(stderr);
                
                // Replace COUNTDOWNLEFT with COUNTDOWNMS value
                try {
                    new_activity_tag = std::regex_replace(new_activity_tag,
                        std::regex(R"(COUNTDOWNLEFT="[^"]*")"),
                        "COUNTDOWNLEFT=\"" + countdownms + "\"");
                } catch (const std::exception& e) {
                    std::fprintf(stderr, "[warn] regex error: %s\n", e.what());
                }
                
                // Set COUNTDOWN_EXPIRED to 0
                try {
                    new_activity_tag = std::regex_replace(new_activity_tag,
                        std::regex(R"(COUNTDOWN_EXPIRED="[^"]*")"),
                        "COUNTDOWN_EXPIRED=\"0\"");
                } catch (const std::exception& e) {
                    std::fprintf(stderr, "[warn] regex error: %s\n", e.what());
                }
            }
        }
    }
    else if (activity_tag.find("TIMERTYPE=\"0\"") != std::string::npos) {
        std::fprintf(stderr, "[info] TIMERTYPE=0 detected, resetting elapsed time\n");
        std::fflush(stderr);
        
        // Set ELAPSED to 0
        try {
            new_activity_tag = std::regex_replace(new_activity_tag,
                std::regex(R"(ELAPSED="[^"]*")"),
                "ELAPSED=\"0\"");
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[warn] regex error: %s\n", e.what());
        }
    }
    else {
        std::fprintf(stderr, "[info] unknown TIMERTYPE, no timer changes made\n");
    }
    
    // Replace the activity tag in result
    result = result.substr(0, activity_pos) + new_activity_tag + result.substr(activity_end + 1);
    
    std::fprintf(stderr, "[info] reset complete\n");
    std::fflush(stderr);
    
    return result;
}

inline std::string reset_file(const std::string& input) {
    std::fprintf(stderr, "[info] decrypting for reset...\n");
    std::fflush(stderr);
    
    std::string xml = is_old_pt(input) ? decrypt_old(input) : decrypt_pka(input);
    
    std::fprintf(stderr, "[info] decrypted, size = %zu\n", xml.size());
    std::fflush(stderr);
    
    xml = reset_activity(xml);
    
    std::fprintf(stderr, "[info] re-encrypting...\n");
    std::fflush(stderr);
    
    return encrypt_pka(xml);
}
// ================================================================
// Release activity - clear recent files, lock features, reset
// ================================================================
inline std::string lock_features(const std::string& xml) {
    if (xml.empty()) return xml;
    
    std::fprintf(stderr, "[info] locking features in XML (%zu bytes)\n", xml.size());
    std::fflush(stderr);
    
    std::string result = xml;
    
    // List of features to lock (change on="no" to on="yes")
    const char* features_to_lock[] = {
        "Switching to Logical",
        "Switching to Physical",
        "Switching to Realtime",
        "Switching to Simulation",
        "Hide Event List on Start",
        "Hide Network Component Box in Wiring Closets",
        "Hide User Created Packet Window",
        "Note Tool",
        "Delete Tool",
        "Inspection Tool",
        "Drawing Tool",
        "Resize Tool",
        "Edit Environment",
        "Hide Wireless/Cellular Connection",
        "Toggling Animation",
        "Toggling Auto Dock Popup Window",
        "Toggling Sound",
        "Toggling Telephony Sound",
        "Toggling Show Port Information",
        "Enable Cable Length",
        "View Assessment Items",
        "View Connectivity Tests",
        "Edit Instructions",
        "Check Results",
        "Reset Activity",
        "Multi-user",
        "Create Devices",
        "Remove Devices",
        "Move Devices",
        "Change Interface",
        "Remove Interface",
        "Connect Links",
        "Disconnect Links",
        "Manage All Cables in Wiring Closet",
        "Create Cluster",
        "Remove Cluster",
        "Enter Cluster",
        "Move Cluster",
        "Create Physical Level",
        "Remove Physical Level",
        "Change Physical Level",
        "Global Tooltip",
        "Change Label",
        "Move Label",
        "Remove Notes/Annotations",
        "Auto Connect",
        "Change Display Names",
        "Change Wireless Coverage Range",
        "Change Bluetooth Transmit Range",
        "Use Thing Editor Tab",
        "Use I/O Devices Tab",
        "Use Attributes Tab"
    };
    
    int lock_count = 0;
    
    // For each feature, use a simpler approach: just replace the on= attribute value
    for (const char* feature : features_to_lock) {
        // Build pattern: <NODE on="no">\n     <ID>feature</ID>
        // We need to handle various whitespace between tags
        
        std::string id_tag = std::string("<ID>") + feature + "</ID>";
        size_t pos = 0;
        
        while ((pos = result.find(id_tag, pos)) != std::string::npos) {
            // Look backwards to find <NODE on="no">
            // Search up to 100 chars back
            size_t search_start = (pos > 100) ? (pos - 100) : 0;
            
            // Find the last occurrence of <NODE between search_start and pos
            size_t last_node = std::string::npos;
            size_t temp_pos = search_start;
            while ((temp_pos = result.find("<NODE ", temp_pos)) != std::string::npos && temp_pos < pos) {
                last_node = temp_pos;
                temp_pos++;
            }
            
            if (last_node == std::string::npos) {
                pos++;
                continue;
            }
            
            // Find the > that closes this NODE tag
            size_t close_bracket = result.find(">", last_node);
            if (close_bracket == std::string::npos || close_bracket >= pos) {
                pos++;
                continue;
            }
            
            // Check if this NODE has on="no"
            std::string node_tag = result.substr(last_node, close_bracket - last_node + 1);
            if (node_tag.find("on=\"no\"") != std::string::npos) {
                // Simply replace on="no" with on="yes" in place
                size_t on_pos = result.find("on=\"no\"", last_node);
                if (on_pos != std::string::npos && on_pos < close_bracket) {
                    result.replace(on_pos + 4, 2, "yes");  // Replace "no" with "yes"
                    lock_count++;
                    std::fprintf(stderr, "[info] locked: %s\n", feature);
                    std::fflush(stderr);
                }
            }
            
            pos++;
        }
    }
    
    std::fprintf(stderr, "[info] locked %d features\n", lock_count);
    std::fflush(stderr);
    
    return result;
}
inline std::string clear_recent_files(const std::string& xml) {
    if (xml.empty()) return xml;
    
    std::fprintf(stderr, "[info] clearing recent files from XML (%zu bytes)\n", xml.size());
    std::fflush(stderr);
    
    std::string result = xml;
    
    // Find and clear all <RECENT_FILES>...</RECENT_FILES> sections
    size_t pos = 0;
    int count = 0;
    
    while ((pos = result.find("<RECENT_FILES>", pos)) != std::string::npos) {
        size_t end = result.find("</RECENT_FILES>", pos);
        if (end == std::string::npos) {
            std::fprintf(stderr, "[warn] unclosed RECENT_FILES tag at position %zu\n", pos);
            break;
        }
        
        end += 15; // length of "</RECENT_FILES>"
        
        // Replace the entire section with empty tags
        result.replace(pos, end - pos, "<RECENT_FILES></RECENT_FILES>");
        count++;
        
        pos += 29; // length of "<RECENT_FILES></RECENT_FILES>"
    }
    
    std::fprintf(stderr, "[info] cleared %d RECENT_FILES section(s)\n", count);
    std::fflush(stderr);
    
    return result;
}

inline std::string set_time_limit(const std::string& xml, unsigned long long time_ms, int timer_type) {
    if (xml.empty()) return xml;
    
    std::fprintf(stderr, "[info] setting timer type to %d", timer_type);
    if (timer_type == 1) {
        std::fprintf(stderr, " (countdown), time limit = %llu ms\n", time_ms);
    } else {
        std::fprintf(stderr, " (elapsed time)\n");
    }
    std::fflush(stderr);
    
    std::string result = xml;
    
    // Set TIMERTYPE
    try {
        result = std::regex_replace(result,
            std::regex(R"(TIMERTYPE="[^"]*")"),
            "TIMERTYPE=\"" + std::to_string(timer_type) + "\"");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[warn] regex error setting TIMERTYPE: %s\n", e.what());
    }
    
    if (timer_type == 1) {
        // Countdown mode - set time values
        std::string time_str = std::to_string(time_ms);
        
        // Replace COUNTDOWNMS="..."
        try {
            result = std::regex_replace(result,
                std::regex(R"(COUNTDOWNMS="[^"]*")"),
                "COUNTDOWNMS=\"" + time_str + "\"");
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[warn] regex error setting COUNTDOWNMS: %s\n", e.what());
        }
        
        // Replace COUNTDOWNLEFT="..."
        try {
            result = std::regex_replace(result,
                std::regex(R"(COUNTDOWNLEFT="[^"]*")"),
                "COUNTDOWNLEFT=\"" + time_str + "\"");
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[warn] regex error setting COUNTDOWNLEFT: %s\n", e.what());
        }
        
        // Reset COUNTDOWN_EXPIRED="0"
        try {
            result = std::regex_replace(result,
                std::regex(R"(COUNTDOWN_EXPIRED="[^"]*")"),
                "COUNTDOWN_EXPIRED=\"0\"");
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[warn] regex error setting COUNTDOWN_EXPIRED: %s\n", e.what());
        }
    } else {
        // Elapsed time mode - reset ELAPSED to 0
        try {
            result = std::regex_replace(result,
                std::regex(R"(ELAPSED="[^"]*")"),
                "ELAPSED=\"0\"");
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[warn] regex error setting ELAPSED: %s\n", e.what());
        }
    }
    
    std::fprintf(stderr, "[info] timer settings applied\n");
    std::fflush(stderr);
    
    return result;
}

inline std::string set_dynamic_feedback(const std::string& xml, int feedback_type) {
    if (xml.empty()) return xml;
    
    const char* type_names[] = {
        "none",
        "item count percentage",
        "score percentage", 
        "item count",
        "score"
    };
    
    std::fprintf(stderr, "[info] setting dynamic feedback to type %d (%s)\n", 
                 feedback_type, (feedback_type >= 0 && feedback_type <= 4) ? type_names[feedback_type] : "unknown");
    std::fflush(stderr);
    
    std::string result = xml;
    
    // Determine the value (true/false)
    std::string value = (feedback_type == 0) ? "false" : "true";
    
    // Replace <DYNAMIC_PERCENTAGE_FEEDBACK TYPE="X">value</DYNAMIC_PERCENTAGE_FEEDBACK>
    try {
        result = std::regex_replace(result,
            std::regex(R"(<DYNAMIC_PERCENTAGE_FEEDBACK TYPE="[^"]*">[^<]*</DYNAMIC_PERCENTAGE_FEEDBACK>)"),
            "<DYNAMIC_PERCENTAGE_FEEDBACK TYPE=\"" + std::to_string(feedback_type) + "\">" + value + "</DYNAMIC_PERCENTAGE_FEEDBACK>");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[warn] regex error setting DYNAMIC_PERCENTAGE_FEEDBACK: %s\n", e.what());
    }
    
    std::fprintf(stderr, "[info] dynamic feedback set\n");
    std::fflush(stderr);
    
    return result;
}

inline std::string release_activity(const std::string& xml, unsigned long long time_limit_ms, int timer_type, int feedback_type) {
    if (xml.empty()) return xml;
    
    std::fprintf(stderr, "[info] releasing activity (clear recent, lock, reset, set time, set feedback)\n");
    std::fflush(stderr);
    
    std::string result = xml;
    
    // Step 1: Clear recent files
    result = clear_recent_files(result);
    
    // Step 2: Lock features
    result = lock_features(result);
    
    // Step 3: Reset activity (same as reset command)
    result = reset_activity(result);
    
    // Step 4: Set timer
    result = set_time_limit(result, time_limit_ms, timer_type);
    
    // Step 5: Set dynamic feedback
    result = set_dynamic_feedback(result, feedback_type);
    
    std::fprintf(stderr, "[info] release complete\n");
    std::fflush(stderr);
    
    return result;
}

inline std::string release_file(const std::string& input, unsigned long long time_limit_ms, int timer_type, int feedback_type) {
    std::fprintf(stderr, "[info] decrypting for release...\n");
    std::fflush(stderr);
    
    std::string xml = is_old_pt(input) ? decrypt_old(input) : decrypt_pka(input);
    
    std::fprintf(stderr, "[info] decrypted, size = %zu\n", xml.size());
    std::fflush(stderr);
    
    xml = release_activity(xml, time_limit_ms, timer_type, feedback_type);
    
    std::fprintf(stderr, "[info] re-encrypting...\n");
    std::fflush(stderr);
    
    return encrypt_pka(xml);
}
}  // namespace pkatool