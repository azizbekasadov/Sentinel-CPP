# Sentinel-CPP

[![Sentinel-CPP-CI](https://github.com/azizbekasadov/Sentinel-CPP/actions/workflows/ci.yml/badge.svg)](https://github.com/azizbekasadov/Sentinel-CPP/actions/workflows/ci.yml) 
[![C++](https://img.shields.io/badge/C%2B%2B-17-brightgreen)](https://isocpp.org)
[![License](https://img.shields.io/badge/license-MIT-brightgreen)](./LICENSE)
[![Contributing](https://img.shields.io/badge/contributing-guide-brightgreen)](./CONTRIBUTING.md)

Project description here.


**Sentinel-CPP** is a high-performance static code analysis tool written in **Modern C++ (17/20)**. 

It is designed for speed and scalability, it leverages
multi-threading to scan large source code repositories for
security vulnerabilities, hardcoded secrets, and unsafe coding
patterns.

## Key Features

* **Concurrent Scanning Engine:** Utilizes a custom Thread Pool to maximize CPU core utilization, significantly reducing scan time for large projects.
* **Extensible Rule System:** Implements a flexible architecture (Strategy Pattern) to easily add new detection rules (Regex, String Matching, or AST-based).
* **Zero-Copy Design Philosophy:** Minimizes memory overhead by using `std::string_view` and move semantics (`std::move`) where applicable.
* **Modern C++ Tooling:** Standard-compliant build process using **CMake**, following LLVM/Google coding styles via `.clang-format`.

## System Architecture

The project follows **Clean Architecture** principles to ensure maintainability and testability:

* **File Crawler:** An abstraction over `std::filesystem` for efficient recursive directory traversal.
* **Task Scheduler (Thread Pool):** A lock-based queue that manages worker threads and balances the scanning load.
* **Rule Engine:** A decoupled logic layer that injects security rules into the scanning process (Dependency Injection).
* **Result Collector:** A thread-safe aggregator for findings using `std::mutex` and atomic operations to ensure data integrity.

### Data Flow Overview
TODO:

## Tech Stack

* **Language:** C++17 (with C++20 features where needed)
* **Build System:** CMake 3.10+ min.
* **Standard Library (STL):** `<filesystem>`, `<thread>`, `<mutex>`, `<regex>`, `<future>` etc. See specs in the codebase.
* **Memory Management:** Strict use of **Smart Pointers** (`std::unique_ptr`, `std::shared_ptr`) to ensure RAII compliance.

## Getting Started

### Prerequisites (check version of the CMake on your device).
* A C++17 compatible compiler (GCC 8+, Clang 7+, or MSVC 2017+)
* CMake 3.10 or higher

### Build Instructions
```bash
# Clone the repository
git clone [https://github.com/azizbekasadov/Sentinel-CPP.git](https://github.com/azizbekasadov/Sentinel-CPP.git)
cd Sentinel-CPP
```

### Build the project
```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Xcode project creation
If you want to use Xcode as an IDE for this project, run the following CMake command

```bash
cmake -G Xcode ..
```

### Run the scanner on a target directory
```bash
./sentinel --path ../examples
```

## Performance & Design Considerations
Concurrency: Instead of spawning a thread per file, the project uses a fixed-size Thread Pool sized to std::thread::hardware_concurrency() to avoid excessive context switching.

Resource Management: Implements RAII for all system resources (file handles, threads, mutexes) to prevent leaks and ensure exception safety.

Scalability: Designed to handle thousands of files by processing data in chunks and minimizing lock contention in the result aggregator.

## Roadmap
- [ ] Integration with LLVM/Clang LibTooling for deeper AST analysis.

- [ ] Support for configuration files in JSON/YAML format.

- [x] CI/CD Integration: GitHub Actions to run Sentinel-CPP on every push.

- [ ] Exporting results to SARIF (Static Analysis Results Interchange Format).


## License

SecureView is released under the MIT license. See [LICENSE](./LICENSE) for details.
