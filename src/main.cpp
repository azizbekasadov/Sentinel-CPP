//
//  main.cpp
//  Sentinel-CPP
//
//  Created by Azizbek Asadov on 01.04.2026.
//

#include <iostream>
#include "Scanner.hpp"

using namespace std;

int main() {
    cout << "Sentinel-CPP is starting..." << endl;
    Scanner scanner;
    cout << scanner.checkFile("anyfile.txt");
    
    return EXIT_SUCCESS;
}
