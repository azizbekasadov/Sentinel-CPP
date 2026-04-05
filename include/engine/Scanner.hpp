//
//  Scanner.hpp
//  Sentinel-CPP
//
//  Created by Azizbek Asadov on 05.04.2026.
//

#ifndef SCANNER_HPP

#define SCANNER_HPP

#include <string>

using namespace std;

class Scanner {
public:
    /// A function to check and validate whether the file exists on the given path
    /// - Parameters:
    ///    - const string &path: provided path to needed file
    bool checkFile(const string &path);
};

#endif
