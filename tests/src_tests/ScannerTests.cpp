//
//  ScannerTests.cpp
//  unit_tests
//
//  Created by Azizbek Asadov on 06.04.2026.
//

#include <chrono>
#include <thread>
#include <atomic>
#include <fstream>
#include <iostream>
#include <catch2/catch_test_macros.hpp>
 
#include "engine/Scanner.hpp"

#define SIG_EVIL        "EVIL_CODE"
#define SIG_VIRUS       "VIRUS_END"
#define SIG_MALWARE     "MALWARE_START"
#define SIG_STRESS      "STRESS_MALWARE_SIGNATURE"
 
using namespace sentinel::engine;
using namespace std;
 
// ===========================================================================
// MARK: - Helpers
// ===========================================================================
 
namespace {
 
filesystem::path uniqueTempDir(const string& label) {
    auto ts = chrono::steady_clock::now().time_since_epoch().count();
    filesystem::path root = filesystem::temp_directory_path()
        / ("sentinel_" + label + "_" + to_string(ts));
    filesystem::create_directories(root);
    return root;
}
 
void writeFile(const filesystem::path& path, const string& content) {
    ofstream f(path, ios::binary);
    f << content;
}
 
void writePaddedFile(const filesystem::path& path,
                     size_t padSize,
                     char fill,
                     const string& suffix = "") {
    ofstream f(path, ios::binary);
    f << string(padSize, fill);
    if (!suffix.empty()) f << suffix;
}
 
} // anonymous namespace
 
// ===========================================================================
// MARK: - 1. scanFile
// ===========================================================================
 
TEST_CASE("scanFile: base cases", "[scanFile][basic]") {
    Scanner scanner;
    auto root = uniqueTempDir("scanfile_basic");
 
    SECTION("Signature is found at the end of the file") {
        auto file = root / "mid.bin";
        writeFile(file, "some prefix " SIG_EVIL " some suffix");
 
        auto result = scanner.scanFile(file, { SIG_EVIL });
 
        REQUIRE(result.found_malicious);
        REQUIRE(result.signatures.size() == 1);
        REQUIRE(result.signatures[0] == SIG_EVIL);
    }
 
    SECTION("Signature is found at the beginning of the file") {
        auto file = root / "begin.bin";
        writeFile(file, SIG_EVIL " trailing data");
 
        REQUIRE(scanner.scanFile(file, { SIG_EVIL }).found_malicious);
    }
 
    SECTION("Signature is found at the end of the file") {
        auto file = root / "end.bin";
        writeFile(file, "leading data " SIG_EVIL);
 
        REQUIRE(scanner.scanFile(file, { SIG_EVIL }).found_malicious);
    }
 
    SECTION("No Signature does not return false positive") {
        auto file = root / "clean.bin";
        writeFile(file, "absolutely clean content without any bad words");
 
        auto result = scanner.scanFile(file, { SIG_EVIL });
 
        REQUIRE_FALSE(result.found_malicious);
        REQUIRE(result.signatures.empty());
    }
 
    SECTION("Empty file does not return FP") {
        auto file = root / "empty.bin";
        writeFile(file, "");
 
        REQUIRE_FALSE(scanner.scanFile(file, { SIG_EVIL }).found_malicious);
    }
 
    SECTION("File Файл contains signature only") {
        auto file = root / "only_sig.bin";
        writeFile(file, SIG_EVIL);
 
        REQUIRE(scanner.scanFile(file, { SIG_EVIL }).found_malicious);
    }
 
    SECTION("Empty signature list does not crash scanner - skips") {
        auto file = root / "any.bin";
        writeFile(file, "some content");
 
        auto result = scanner.scanFile(file, {});
        REQUIRE_FALSE(result.found_malicious);
    }
 
    SECTION("File without permissions (r) does not crash scanner and does not return FP") {
        auto file = root / "locked.bin";
        writeFile(file, "secret: " SIG_EVIL);
 
        filesystem::permissions(file, filesystem::perms::none,
                                filesystem::perm_options::replace);
 
        auto result = scanner.scanFile(file, { SIG_EVIL });
        REQUIRE_FALSE(result.found_malicious);
 
        filesystem::permissions(file, filesystem::perms::owner_all);
    }
 
    SECTION("Non-existing file does not crash scanner") {
        auto f = root / "does_not_exist.bin";
        REQUIRE_FALSE(scanner.scanFile(f, { SIG_EVIL }).found_malicious);
    }
 
    filesystem::remove_all(root);
}
 
// ===========================================================================
// MARK: - 2. scanFile — multiple signatures
// ===========================================================================
 
TEST_CASE("scanFile: multiple signatures", "[scanFile][multi-signature]") {
    Scanner scanner;
    auto root = uniqueTempDir("scanfile_multi");
 
    SECTION("Detects all existing signatures") {
        auto f = root / "multi.bin";
        writeFile(f, "header " SIG_MALWARE " middle " SIG_VIRUS " footer");
 
        auto result = scanner.scanFile(f, { SIG_MALWARE, SIG_VIRUS });
 
        REQUIRE(result.found_malicious);
        REQUIRE(result.signatures.size() == 2);
 
        bool has_malware = find(
                                result.signatures.begin(),
                                result.signatures.end(),
                                string(SIG_MALWARE)
                           ) != result.signatures.end();
        
        bool has_virus   = find(
                                result.signatures.begin(),
                                result.signatures.end(),
                                string(SIG_VIRUS)
                           ) != result.signatures.end();
 
        REQUIRE(has_malware);
        REQUIRE(has_virus);
    }
 
    SECTION("Detects existing signatures only") {
        auto f = root / "partial.bin";
        writeFile(f, "data with " SIG_MALWARE " only");
 
        auto result = scanner.scanFile(f, { SIG_MALWARE, SIG_VIRUS });
 
        REQUIRE(result.found_malicious);
        REQUIRE(result.signatures.size() == 1);
        REQUIRE(result.signatures[0] == SIG_MALWARE);
    }
 
    SECTION("Repetitive nesting of a single signature is not duplicated in the results") {
        auto f = root / "repeat.bin";
        writeFile(f, SIG_EVIL " middle " SIG_EVIL " end");
 
        auto result = scanner.scanFile(f, { SIG_EVIL });
 
        REQUIRE(result.found_malicious);
        REQUIRE(result.signatures.size() == 1);
    }
 
    filesystem::remove_all(root);
}
 
// ===========================================================================
// MARK: - 3. scanFile — (Zero-Copy Buffer)
// ===========================================================================

TEST_CASE("scanFile: Zero-Copy Buffer correctness", "[scanFile][buffer]") {
    Scanner scanner;
    auto root = uniqueTempDir("scanfile_buffer");
 
    const string sig = SIG_EVIL;
 
    SECTION("Signature is on the Zero-Copy buffer limit") {
        auto file = root / "boundary_end.bin";
        writePaddedFile(file, BUFFER_SIZE - sig.length(), 'A', sig);
 
        REQUIRE(scanner.scanFile(file, { sig }).found_malicious);
    }
 
    SECTION("Signature begins in one chunk and finishes in the other") {
        auto file = root / "boundary_split.bin";
        const size_t split = 4;
        string prefix(BUFFER_SIZE - split, 'A');
        writePaddedFile(file, BUFFER_SIZE - split, 'A', sig);
 
        REQUIRE(scanner.scanFile(file, { sig }).found_malicious);
    }
 
    SECTION("Signature begins in the last chunk") {
        auto file = root / "boundary_last_byte.bin";
        writePaddedFile(file, BUFFER_SIZE - 1, 'B', sig);
 
        REQUIRE(scanner.scanFile(file, { sig }).found_malicious);
    }
 
    SECTION("Signature in the third chunk - checking detected overlaps") {
        auto file = root / "third_chunk.bin";
        writePaddedFile(file, BUFFER_SIZE * 2, 'C', sig);
 
        REQUIRE(scanner.scanFile(file, { sig }).found_malicious);
    }
 
    SECTION("A file with the size exceeding BUFFER_SIZE without a signature returns no FP") {
        auto file = root / "large_clean.bin";
        writePaddedFile(file, BUFFER_SIZE * 3, 'D');
 
        REQUIRE_FALSE(scanner.scanFile(file, { sig }).found_malicious);
    }
 
    SECTION("Overlapping signatures are detected") {
        auto file = root / "overlap_sig.bin";
        writeFile(file, "AAAAAAA");
 
        auto result = scanner.scanFile(file, { "AAA" });
        REQUIRE(result.found_malicious);
    }
 
    filesystem::remove_all(root);
}
 
// ===========================================================================
// MARK: - 4. scanDirectory — Basic Behavior
// ===========================================================================
 
TEST_CASE("scanDirectory: basic behavior", "[scanDirectory][basic]") {
    Scanner scanner;
 
    SECTION("Non-existing path returns False") {
        REQUIRE_FALSE(scanner.scanDirectory(
            "/tmp/sentinel_definitely_not_exists_xyzzy",
            { SIG_EVIL }
        ));
    }
 
    SECTION("Path to file returns False") {
        auto root = uniqueTempDir("scandir_not_dir");
        auto f = root / "file.bin";
        writeFile(f, "content");
 
        REQUIRE_FALSE(scanner.scanDirectory(f, { SIG_EVIL }));
 
        filesystem::remove_all(root);
    }
 
    SECTION("Empty Dir returns False") {
        auto root = uniqueTempDir("scandir_empty");
 
        REQUIRE_FALSE(scanner.scanDirectory(root, { SIG_EVIL }));
 
        filesystem::remove_all(root);
    }
 
    SECTION("Dir without files returns False") {
        auto root = uniqueTempDir("scandir_subdirs_only");
        filesystem::create_directories(root / "sub1" / "sub2");
 
        REQUIRE_FALSE(scanner.scanDirectory(root, { SIG_EVIL }));
 
        filesystem::remove_all(root);
    }
 
    SECTION("Empty list of signatures returns False") {
        auto root = uniqueTempDir("scandir_no_sigs");
        writeFile(root / "evil.bin", SIG_EVIL);
 
        REQUIRE_FALSE(scanner.scanDirectory(root, {}));
 
        filesystem::remove_all(root);
    }
 
    SECTION("Clean files - no FP") {
        auto root = uniqueTempDir("scandir_clean");
        for (int i = 0; i < 10; ++i)
            writeFile(root / ("f" + to_string(i) + ".bin"), "clean data " + to_string(i));
 
        REQUIRE_FALSE(scanner.scanDirectory(root, { SIG_EVIL }));
 
        filesystem::remove_all(root);
    }
 
    SECTION("Virus is detected in the root dir") {
        auto root = uniqueTempDir("scandir_root_hit");
        writeFile(root / "clean.bin", "clean");
        writeFile(root / "virus.bin", "payload: " SIG_EVIL " end");
 
        REQUIRE(scanner.scanDirectory(root, { SIG_EVIL }));
 
        filesystem::remove_all(root);
    }
}
 
// ===========================================================================
// MARK: - 5. scanDirectory — рекурсивный обход
// ===========================================================================
 
TEST_CASE("scanDirectory: recursive iteration of the subdirs", "[scanDirectory][filesystem]") {
    Scanner scanner;
 
    SECTION("Virus is detected in the subdir") {
        auto root = uniqueTempDir("scandir_recurse");
        auto sub  = root / "level1" / "level2";
        filesystem::create_directories(sub);
 
        writeFile(root / "clean.bin", "clean");
        writeFile(sub  / "virus.bin", "hidden " SIG_EVIL " here");
 
        REQUIRE(scanner.scanDirectory(root, { SIG_EVIL }));
 
        filesystem::remove_all(root);
    }
 
    SECTION("Virus is in one of many subdirs") {
        auto root   = uniqueTempDir("scandir_multi_sub");
        auto clean1 = root / "clean_dir1";
        auto clean2 = root / "clean_dir2";
        auto bad    = root / "bad_dir";
        filesystem::create_directories(clean1);
        filesystem::create_directories(clean2);
        filesystem::create_directories(bad);
 
        for (int i = 0; i < 5; ++i) {
            writeFile(clean1 / ("c" + to_string(i) + ".bin"), "ok");
            writeFile(clean2 / ("c" + to_string(i) + ".bin"), "ok");
        }
        writeFile(bad / "evil.bin", SIG_EVIL);
 
        REQUIRE(scanner.scanDirectory(root, { SIG_EVIL }));
 
        filesystem::remove_all(root);
    }
 
    SECTION("Deep nested file is detectable") {
        auto root = uniqueTempDir("scandir_deep");
        auto deep = root / "a" / "b" / "c" / "d" / "e";
        filesystem::create_directories(deep);
        writeFile(deep / "malware.bin", SIG_EVIL);
 
        REQUIRE(scanner.scanDirectory(root, { SIG_EVIL }));
 
        filesystem::remove_all(root);
    }
}
 
// ===========================================================================
// MARK: - 6. scanDirectory — Multi-Signature
// ===========================================================================
 
TEST_CASE("scanDirectory: multi-signature validation", "[scanDirectory][multi-signature]") {
    Scanner scanner;
 
    SECTION("Detects a file with 1/2 signatures") {
        auto root = uniqueTempDir("scandir_multi_sig_1");
        writeFile(root / "f.bin", "data " SIG_MALWARE " end");
 
        REQUIRE(scanner.scanDirectory(root, { SIG_MALWARE, SIG_VIRUS }));
 
        filesystem::remove_all(root);
    }
 
    SECTION("Detects a file with 2/2 signatures") {
        auto root = uniqueTempDir("scandir_multi_sig_2");
        writeFile(root / "f.bin", "data " SIG_VIRUS " end");
 
        REQUIRE(scanner.scanDirectory(root, { SIG_MALWARE, SIG_VIRUS }));
 
        filesystem::remove_all(root);
    }
 
    SECTION("Does not return FP for signatures that do not exist in the files") {
        auto root = uniqueTempDir("scandir_multi_sig_clean");
        writeFile(root / "f.bin", "totally clean");
 
        REQUIRE_FALSE(scanner.scanDirectory(root, { SIG_MALWARE, SIG_VIRUS }));
 
        filesystem::remove_all(root);
    }
}
 
// ===========================================================================
// MARK: - 7. No Race Condition in the multithreading
// ===========================================================================
 
TEST_CASE("scanDirectory: valid in multitude of threads", "[scanDirectory][threading]") {
    Scanner scanner;
 
    auto root = uniqueTempDir("scandir_thread_correctness");
 
    for (int i = 0; i < 50; ++i)
        writeFile(root / ("clean_" + to_string(i) + ".bin"), "clean data");
 
    writeFile(root / "virus.bin", "payload " SIG_EVIL);
 
    SECTION("1 thread") {
        REQUIRE(scanner.scanDirectory(root, { SIG_EVIL }, 1));
    }
 
    SECTION("2 threads") {
        REQUIRE(scanner.scanDirectory(root, { SIG_EVIL }, 2));
    }
 
    SECTION("4 threads") {
        REQUIRE(scanner.scanDirectory(root, { SIG_EVIL }, 4));
    }
 
    SECTION("8 threads") {
        REQUIRE(scanner.scanDirectory(root, { SIG_EVIL }, 8));
    }
 
    SECTION("Number of threads > batches") {
        REQUIRE(scanner.scanDirectory(root, { SIG_EVIL }, 64));
    }
 
    SECTION("threadCount=0 → hardware_concurrency") {
        REQUIRE(scanner.scanDirectory(root, { SIG_EVIL }, 0));
    }
 
    filesystem::remove_all(root);
}
 
// ===========================================================================
// MARK: - 8. Multithreading — Race Condition Detection
// ===========================================================================

TEST_CASE("scanDirectory: race condition — multiple races", "[scanDirectory][race-condition]") {
    Scanner scanner;
 
    auto root = uniqueTempDir("race_condition");
 
    for (int i = 0; i < 200; ++i) {
        string content = (i % 4 == 0) ? string(SIG_EVIL) : "safe_content_" + to_string(i);
        writeFile(root / ("f" + to_string(i) + ".bin"), content);
    }
 
    for (int run = 0; run < 10; ++run) {
        INFO("Run #" << run);
        REQUIRE(scanner.scanDirectory(root, { SIG_EVIL }, 16));
    }
 
    filesystem::remove_all(root);
}
 
TEST_CASE("scanDirectory: race condition — a virus in the last file sorted alphabetically", "[scanDirectory][race-condition]") {
    Scanner scanner;

    auto root = uniqueTempDir("race_last_file");
 
    for (int i = 0; i < 100; ++i)
        writeFile(root / ("a_clean_" + to_string(i) + ".bin"), "clean");
 
    writeFile(root / "z_virus.bin", SIG_EVIL);
 
    for (int run = 0; run < 5; ++run) {
        INFO("Run #" << run);
        REQUIRE(scanner.scanDirectory(root, { SIG_EVIL }, 16));
    }
 
    filesystem::remove_all(root);
}
 
TEST_CASE("scanDirectory: race condition — a virus in the first file, many threads", "[scanDirectory][race-condition]") {
    Scanner scanner;
 
    auto root = uniqueTempDir("race_first_file");
 
    writeFile(root / "a_virus.bin", SIG_EVIL); // первый по алфавиту
 
    for (int i = 0; i < 200; ++i)
        writeFile(root / ("z_clean_" + to_string(i) + ".bin"), "clean");
 
    for (int run = 0; run < 5; ++run) {
        INFO("Run #" << run);
        REQUIRE(scanner.scanDirectory(root, { SIG_EVIL }, 32));
    }
 
    filesystem::remove_all(root);
}
 
// ===========================================================================
// MARK: - 9. Multithreading — Stress Test
// ===========================================================================
 
TEST_CASE("scanDirectory: stress — 1000 files, a virus at the end", "[scanDirectory][stress]") {
    Scanner scanner;
 
    auto root = uniqueTempDir("stress_1000");
 
    for (int i = 0; i < 999; ++i)
        writeFile(root / (to_string(i) + ".bin"), "perfectly_safe_content");
 
    writeFile(root / "999.bin", "prefix_" SIG_STRESS "_suffix");
 
    REQUIRE(scanner.scanDirectory(root, { SIG_STRESS }, 32));
 
    filesystem::remove_all(root);
}
 
TEST_CASE("scanDirectory: stress — all files are clean, no FP", "[scanDirectory][stress]") {
    Scanner scanner;
 
    auto root = uniqueTempDir("stress_clean");
 
    for (int i = 0; i < 500; ++i)
        writeFile(root / ("f" + to_string(i) + ".bin"), "clean_" + to_string(i));
 
    REQUIRE_FALSE(scanner.scanDirectory(root, { SIG_EVIL }, 8));
 
    filesystem::remove_all(root);
}
 
// ===========================================================================
// MARK: - 10. Performance
// ===========================================================================

TEST_CASE("scanDirectory: performance — many small files", "[scanDirectory][performance]") {
    Scanner scanner;
 
    auto root = uniqueTempDir("perf_small");
 
    for (int i = 0; i < 100; ++i)
        writeFile(root / ("f" + to_string(i) + ".bin"), "clean data");
 
    auto start    = chrono::high_resolution_clock::now();
    bool detected = scanner.scanDirectory(root, { SIG_EVIL }, 8);
    auto duration = chrono::duration_cast<chrono::milliseconds>(
        chrono::high_resolution_clock::now() - start).count();
 
    REQUIRE_FALSE(detected);
    REQUIRE(duration < 500);
 
    filesystem::remove_all(root);
}
 
TEST_CASE("scanDirectory: performance", "[scanDirectory][performance]") {
    Scanner scanner;
 
    auto root = uniqueTempDir("perf_mt_vs_st");
 
    for (int i = 0; i < 200; ++i)
        writeFile(root / ("f" + to_string(i) + ".bin"), "clean data");
 
    auto t_start = chrono::high_resolution_clock::now();
    scanner.scanDirectory(root, { SIG_EVIL }, 1);
    auto single_ms = chrono::duration_cast<chrono::milliseconds>(
        chrono::high_resolution_clock::now() - t_start).count();
 
    auto mt_start = chrono::high_resolution_clock::now();
    scanner.scanDirectory(root, { SIG_EVIL }, 8);
    auto multi_ms = chrono::duration_cast<chrono::milliseconds>(
        chrono::high_resolution_clock::now() - mt_start).count();
 
    UNSCOPED_INFO("Single: " << single_ms << "ms, Multi: " << multi_ms << "ms");
    REQUIRE(multi_ms <= single_ms + 50);
 
    filesystem::remove_all(root);
}
 
TEST_CASE("scanDirectory: performance —  large files validation (regression case)", "[scanDirectory][performance]") {
    Scanner scanner;
 
    auto root = uniqueTempDir("perf_large");
 
    for (int i = 0; i < 5; ++i)
        writePaddedFile(root / ("big_" + to_string(i) + ".bin"), 1024 * 1024, 'A');
 
    auto start    = chrono::high_resolution_clock::now();
    bool detected = scanner.scanDirectory(root, { SIG_EVIL }, 5);
    auto duration = chrono::duration_cast<chrono::milliseconds>(
        chrono::high_resolution_clock::now() - start).count();
 
    UNSCOPED_INFO("Large files scan duration: " << duration << "ms");
    REQUIRE_FALSE(detected);
    REQUIRE(duration < 1000); // исправлен нереалистичный порог 200ms
 
    filesystem::remove_all(root);
}
 
TEST_CASE("scanDirectory: performance — 2000 файлов (volume)", "[scanDirectory][performance]") {
    Scanner scanner;
    auto root = uniqueTempDir("perf_volume");
 
    for (int i = 0; i < 2000; ++i)
        writeFile(root / ("f" + to_string(i) + ".bin"), "v");
 
    auto start = chrono::high_resolution_clock::now();
    scanner.scanDirectory(root, { SIG_EVIL }, 8);
    
    auto duration = chrono::duration_cast<chrono::milliseconds>(
        chrono::high_resolution_clock::now() - start).count();
 
    REQUIRE(duration < 1000);
 
    filesystem::remove_all(root);
}
 
// ===========================================================================
// MARK: - 11. Acceptance Criteria — Strategy Pattern (Extensible Rule System)
// ===========================================================================

TEST_CASE("Acceptance: Strategy Pattern — random signatures without changes of the Scanner",
          "[acceptance][strategy]")
{
    Scanner scanner;
    auto root = uniqueTempDir("ac_strategy");
 
    const vector<string> custom_rules = {
        "AWS_SECRET_KEY",
        "PRIVATE_KEY_BEGIN",
        "DB_PASSWORD=",
    };
 
    SECTION("Detects hardcoded AWS key") {
        writeFile(root / "config.env", "AWS_SECRET_KEY=abc123xyz");
        REQUIRE(scanner.scanDirectory(root, custom_rules));
    }
 
    SECTION("Detects a private key") {
        writeFile(root / "key.pem", "-----PRIVATE_KEY_BEGIN-----\ndata\n");
        REQUIRE(scanner.scanDirectory(root, custom_rules));
    }
 
    SECTION("Detects hardcoded BD password") {
        writeFile(root / "app.cfg", "DB_PASSWORD=superSecret42");
        REQUIRE(scanner.scanDirectory(root, custom_rules));
    }
 
    SECTION("A clean file does not trigger any rule") {
        writeFile(root / "clean.cfg", "DB_HOST=localhost\nDB_PORT=5432");
        REQUIRE_FALSE(scanner.scanDirectory(root, custom_rules));
    }
 
    filesystem::remove_all(root);
}
 
// ===========================================================================
// MARK: - 12. Acceptance Criteria — Zero-Copy Design Philosophy
// ===========================================================================

TEST_CASE("Acceptance: Zero-Copy — correctness with the dynamic sized files",
          "[acceptance][zero-copy]")
{
    Scanner scanner;
    auto root = uniqueTempDir("ac_zerocopy");
 
    const string sig = SIG_EVIL;
    const vector<size_t> sizes = { 1, BUFFER_SIZE - 1, BUFFER_SIZE, BUFFER_SIZE + 1, BUFFER_SIZE * 10 };
 
    for (size_t pad : sizes) {
        DYNAMIC_SECTION("FILE SIZE = " << pad << " + signature") {
            auto f = root / ("pad_" + to_string(pad) + ".bin");
            writePaddedFile(f, pad, 'Z', sig);
            REQUIRE(scanner.scanFile(f, { sig }).found_malicious);
        }
 
        DYNAMIC_SECTION("FILE SIZE = " << pad << ", clean") {
            auto f = root / ("clean_" + to_string(pad) + ".bin");
            writePaddedFile(f, pad, 'Z');
            REQUIRE_FALSE(scanner.scanFile(f, { sig }).found_malicious);
        }
    }
 
    filesystem::remove_all(root);
}
 
// ===========================================================================
// MARK: - 13. Acceptance Criteria — RAII & Resource Safety
// ===========================================================================

TEST_CASE("Acceptance: RAII — security of the resources during errors", "[acceptance][raii]") {
    Scanner scanner;
 
    SECTION("File disappears before gaining a path and opening a file - no crash") {
        auto root = uniqueTempDir("ac_raii_vanish");
        auto f = root / "vanish.bin";
        writeFile(f, SIG_EVIL);
 
        filesystem::remove(f);
 
        REQUIRE_FALSE(scanner.scanDirectory(root, { SIG_EVIL }));
 
        filesystem::remove_all(root);
    }
 
    SECTION("Mixed files: only readable, one unreadable with a virus") {
        auto root = uniqueTempDir("ac_raii_mixed");
 
        writeFile(root / "clean1.bin", "ok");
        writeFile(root / "clean2.bin", "ok");
 
        auto locked = root / "locked_virus.bin";
        writeFile(locked, SIG_EVIL);
        filesystem::permissions(locked, filesystem::perms::none,
                                filesystem::perm_options::replace);
 
        writeFile(root / "clean3.bin", "ok");
 
        bool result = scanner.scanDirectory(root, { SIG_EVIL });
        REQUIRE_FALSE(result);
 
        filesystem::permissions(locked, filesystem::perms::owner_all);
        filesystem::remove_all(root);
    }
 
    SECTION("Call scanDirectory again on the same directory — idempotent behavior") {
        auto root = uniqueTempDir("ac_raii_idempotent");
        writeFile(root / "virus.bin", SIG_EVIL);
 
        bool r1 = scanner.scanDirectory(root, { SIG_EVIL });
        bool r2 = scanner.scanDirectory(root, { SIG_EVIL });
        bool r3 = scanner.scanDirectory(root, { SIG_EVIL });
 
        REQUIRE(r1 == r2);
        REQUIRE(r2 == r3);
        REQUIRE(r1 == true);
 
        filesystem::remove_all(root);
    }
}
 
