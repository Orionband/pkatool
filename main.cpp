#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

#include "pkatool.hpp"

// ----------------------------------------------------------------
// Windows crash handler — catches access violations etc. that
// C++ try/catch cannot intercept.
// ----------------------------------------------------------------
#ifdef _WIN32
static LONG WINAPI crash_handler(EXCEPTION_POINTERS *info) {
    DWORD code = info->ExceptionRecord->ExceptionCode;
    std::fprintf(stderr,
        "[fatal] Windows exception 0x%08lX at address %p\n",
        code, info->ExceptionRecord->ExceptionAddress);
    std::fflush(stderr);
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

// ----------------------------------------------------------------
// File I/O helpers — always binary, always checked
// ----------------------------------------------------------------
static std::string read_binary_file(const char *path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f.is_open()) {
        std::fprintf(stderr, "[error] cannot open input file: %s\n", path);
        std::fflush(stderr);
        std::exit(1);
    }
    std::streamsize size = f.tellg();
    if (size <= 0) {
        std::fprintf(stderr, "[error] input file is empty: %s\n", path);
        std::fflush(stderr);
        std::exit(1);
    }
    f.seekg(0, std::ios::beg);
    std::string data(static_cast<std::size_t>(size), '\0');
    if (!f.read(&data[0], size)) {
        std::fprintf(stderr, "[error] failed reading: %s\n", path);
        std::fflush(stderr);
        std::exit(1);
    }
    f.close();

    // Diagnostic: size + hex dump of first 16 bytes
    std::fprintf(stderr, "[info] read %lld bytes from %s\n",
                 (long long)size, path);
    std::fprintf(stderr, "[info] first bytes:");
    int n = (size < 16) ? (int)size : 16;
    for (int i = 0; i < n; i++) {
        std::fprintf(stderr, " %02x",
                     static_cast<unsigned char>(data[i]));
    }
    std::fprintf(stderr, "\n");
    std::fflush(stderr);

    return data;
}

static void write_binary_file(const char *path, const std::string &data) {
    if (data.empty()) {
        std::fprintf(stderr, "[error] refusing to write 0 bytes to %s\n", path);
        std::fflush(stderr);
        std::exit(1);
    }
    std::ofstream f(path, std::ios::binary);
    if (!f.is_open()) {
        std::fprintf(stderr, "[error] cannot open output file: %s\n", path);
        std::fflush(stderr);
        std::exit(1);
    }
    f.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!f.good()) {
        std::fprintf(stderr, "[error] write failed to: %s\n", path);
        std::fflush(stderr);
        std::exit(1);
    }
    f.close();
    std::fprintf(stderr, "[info] wrote %llu bytes to %s\n",
                 (unsigned long long)data.size(), path);
    std::fflush(stderr);
}

// ----------------------------------------------------------------
static void help() {
    std::printf(R"(usage: pkatool <option> [args...]

options:
  -d <in> <out>   decrypt pka/pkt to xml
  -e <in> <out>   encrypt xml to pka/pkt
  -f <in> <out>   patch file to be opened by any PT version
  -p <in> <out>   remove password from activity file
  -u <in> <out>   unlock all locked features in activity file
  -r <in> <out>   reset activity (restore initial network, reset timer)
  -l <in> <out>   release activity (clear recent, lock, feedback, timer, reset)
  -x <in> <base>  extract networks (creates <base>_current.pkt, etc)
  -nets <in>      decrypt packet tracer "nets" file
  -logs <in>      decrypt packet tracer log file
  --forge <out>   forge authentication file

examples:
  pkatool -d foobar.pka foobar.xml
  pkatool -e foobar.xml foobar.pka
  pkatool -f old.pka fixed.pka
  pkatool -p pwlocked.pka pwunlocked.pka
  pkatool -u restricted.pka unrestricted.pka
  pkatool -r expired.pka reset.pka
  pkatool -l draft.pka release.pka
  pkatool -x activity.pka networks
)");
    std::exit(0);
}

// ----------------------------------------------------------------
int main(int argc, char *argv[]) {
#ifdef _WIN32
    SetUnhandledExceptionFilter(crash_handler);
#endif

    if (argc < 2) help();

    std::string action = argv[1];

    try {
        // --- decrypt pka/pkt → xml ---
        if (action == "-d" && argc >= 4) {
            std::fprintf(stderr, "[info] decrypt: %s -> %s\n", argv[2], argv[3]);
            std::fflush(stderr);

            std::string input = read_binary_file(argv[2]);

            std::fprintf(stderr, "[info] detecting format...\n");
            std::fflush(stderr);

            std::string xml;
            if (pkatool::is_old_pt(input)) {
                std::fprintf(stderr, "[info] detected OLD format (pre-PT5)\n");
                std::fflush(stderr);
                xml = pkatool::decrypt_old(input);
            } else {
                std::fprintf(stderr, "[info] detected NEW format (Twofish-EAX)\n");
                std::fflush(stderr);
                xml = pkatool::decrypt_pka(input);
            }

            std::fprintf(stderr, "[info] decryption succeeded, xml size = %llu\n",
                         (unsigned long long)xml.size());
            std::fflush(stderr);

            write_binary_file(argv[3], xml);
            std::fprintf(stderr, "[done]\n");
        }
        // --- encrypt xml → pka/pkt ---
        else if (action == "-e" && argc >= 4) {
            std::fprintf(stderr, "[info] encrypt: %s -> %s\n", argv[2], argv[3]);
            std::fflush(stderr);

            std::string input = read_binary_file(argv[2]);
            std::string output = pkatool::encrypt_pka(input);

            std::fprintf(stderr, "[info] encryption succeeded, size = %llu\n",
                         (unsigned long long)output.size());
            std::fflush(stderr);

            write_binary_file(argv[3], output);
            std::fprintf(stderr, "[done]\n");
        }
        // --- fix version ---
        else if (action == "-f" && argc >= 4) {
            std::fprintf(stderr, "[info] fix: %s -> %s\n", argv[2], argv[3]);
            std::fflush(stderr);

            std::string input = read_binary_file(argv[2]);
            std::string output = pkatool::fix(input);

            write_binary_file(argv[3], output);
            std::fprintf(stderr, "[done]\n");
        }
        // --- remove password ---
        else if (action == "-p" && argc >= 4) {
            std::fprintf(stderr, "[info] remove password: %s -> %s\n", argv[2], argv[3]);
            std::fflush(stderr);

            std::string input = read_binary_file(argv[2]);
            std::string output = pkatool::remove_password_from_file(input);

            write_binary_file(argv[3], output);
            std::fprintf(stderr, "[done]\n");
        }
        // --- unlock ---
        else if (action == "-u" && argc >= 4) {
            std::fprintf(stderr, "[info] unlock: %s -> %s\n", argv[2], argv[3]);
            std::fflush(stderr);

            std::string input = read_binary_file(argv[2]);
            std::string output = pkatool::unlock_file(input);

            write_binary_file(argv[3], output);
            std::fprintf(stderr, "[done]\n");
        }
        // --- reset activity ---
        else if (action == "-r" && argc >= 4) {
            std::fprintf(stderr, "[info] reset: %s -> %s\n", argv[2], argv[3]);
            std::fflush(stderr);

            std::string input = read_binary_file(argv[2]);
            std::string output = pkatool::reset_file(input);

            write_binary_file(argv[3], output);
            std::fprintf(stderr, "[done]\n");
        }
		else if (action == "-l" && argc >= 4) {
            std::fprintf(stderr, "[info] release: %s -> %s\n", argv[2], argv[3]);
            std::fflush(stderr);

            // Prompt for time limit
            std::printf("Enter time limit in minutes (0 for no time limit): ");
            std::fflush(stdout);
            
            int time_minutes = 0;
            if (std::scanf("%d", &time_minutes) != 1) {
                time_minutes = 0;
            }
            
            unsigned long long time_ms = 0;
            int timer_type = 0;
            
            if (time_minutes > 0) {
                time_ms = static_cast<unsigned long long>(time_minutes) * 60ULL * 1000ULL;
                timer_type = 1;
                std::fprintf(stderr, "[info] time limit set to %d minutes (%llu ms)\n", 
                             time_minutes, time_ms);
            } else {
                timer_type = 0;
                std::fprintf(stderr, "[info] no time limit (elapsed time mode)\n");
            }
            std::fflush(stderr);
            
            // Prompt for dynamic feedback mode
            std::printf("\nDynamic Feedback Mode:\n");
            std::printf("  0 - None\n");
            std::printf("  1 - Show item count percentage\n");
            std::printf("  2 - Show score percentage\n");
            std::printf("  3 - Show item count\n");
            std::printf("  4 - Show score\n");
            std::printf("Enter feedback mode (0-4): ");
            std::fflush(stdout);
            
            int feedback_type = 0;
            if (std::scanf("%d", &feedback_type) != 1) {
                feedback_type = 0;
            }
            
            // Validate feedback type
            if (feedback_type < 0 || feedback_type > 4) {
                std::fprintf(stderr, "[warn] invalid feedback type %d, defaulting to 0 (none)\n", feedback_type);
                feedback_type = 0;
            }
            
            std::fprintf(stderr, "[info] feedback mode set to %d\n", feedback_type);
            std::fflush(stderr);

            std::string input = read_binary_file(argv[2]);
            std::string output = pkatool::release_file(input, time_ms, timer_type, feedback_type);

            write_binary_file(argv[3], output);
            
            std::fprintf(stderr, "\n");
            std::fprintf(stderr, "========================================\n");
            std::fprintf(stderr, "IMPORTANT: Create a password to protect\n");
            std::fprintf(stderr, "the activity using Activity Wizard!\n");
            std::fprintf(stderr, "========================================\n");
            std::fprintf(stderr, "\n");
            std::fflush(stderr);
            
            std::fprintf(stderr, "[done]\n");
        }// --- extract networks ---
        else if (action == "-x" && argc >= 4) {
            std::fprintf(stderr, "[info] extract networks: %s -> %s_*.pkt\n", argv[2], argv[3]);
            std::fflush(stderr);

            std::string input = read_binary_file(argv[2]);
            
            // Call the extraction function
            pkatool::extract_and_save_networks(input, argv[3]);
            
            std::fprintf(stderr, "[done]\n");
        }
        // --- decrypt logs ---
        else if (action == "-logs" && argc >= 3) {
            std::fprintf(stderr, "[info] decrypt logs: %s\n", argv[2]);
            std::fflush(stderr);

            std::ifstream f(argv[2], std::ios::binary);
            if (!f.is_open()) {
                std::fprintf(stderr, "[error] cannot open: %s\n", argv[2]);
                return 1;
            }
            std::string line;
            int count = 0;
            while (std::getline(f, line)) {
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();
                if (!line.empty()) {
                    std::cout << pkatool::decrypt_logs(line) << std::endl;
                    count++;
                }
            }
            f.close();
            std::fprintf(stderr, "[done] decrypted %d log lines\n", count);
        }
        // --- decrypt nets ---
        else if (action == "-nets" && argc >= 3) {
            std::fprintf(stderr, "[info] decrypt nets: %s\n", argv[2]);
            std::fflush(stderr);

            std::string input = read_binary_file(argv[2]);
            std::string output = pkatool::decrypt_nets(input);
            std::cout << output << std::endl;
            std::fprintf(stderr, "[done]\n");
        }
        // --- forge ---
        else if (action == "--forge" && argc >= 3) {
            std::fprintf(stderr, "[info] forging auth file: %s\n", argv[2]);
            std::fflush(stderr);

            std::string output =
                pkatool::encrypt_nets("foobar~foobar~foobar~foobar~1700000000");
            write_binary_file(argv[2], output);
            std::fprintf(stderr, "[done]\n");
        }
        else {
            help();
        }
    }
    catch (const CryptoPP::Exception &e) {
        std::fprintf(stderr,
            "\n[cryptopp error] %s\n"
            "This usually means the file uses a different encryption\n"
            "format, different keys, or is corrupted.\n",
            e.what());
        std::fflush(stderr);
        return 1;
    }
    catch (const std::exception &e) {
        std::fprintf(stderr, "\n[error] %s\n", e.what());
        std::fflush(stderr);
        return 1;
    }
    catch (int code) {
        const char *reason = "unknown";
        if (code == -3) reason = "Z_DATA_ERROR (corrupt compressed data)";
        if (code == -4) reason = "Z_MEM_ERROR";
        if (code == -5) reason = "Z_BUF_ERROR";
        std::fprintf(stderr, "\n[zlib error] code=%d (%s)\n", code, reason);
        std::fflush(stderr);
        return 1;
    }
    catch (...) {
        std::fprintf(stderr, "\n[error] unknown/uncaught exception\n");
        std::fflush(stderr);
        return 1;
    }

    std::fflush(stderr);
    return 0;
}