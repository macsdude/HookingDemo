#include <iostream>
#include <windows.h>

int main() {

std::string s;
std::cout << "Programme paused. Enter text to proceed." << std::endl;
std::cin >> s;

// DLL injection occurs here

MessageBoxA(NULL, "Test text", "Test Title", 0);
return 0;

}