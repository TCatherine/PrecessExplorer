#define _CRT_SECURE_NO_WARNINGS

#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <string>
#include <array>

std::string GetIpInfo(const char* IP) {
    std::array<char, 128> buffer;
    std::string result;

    const char* ruta1 = "curl http://ip-api.com/line/";
    char* RutaFinal = new char[strlen(ruta1) + strlen(IP) + 1];
    strcpy(RutaFinal, ruta1);
    strcat(RutaFinal, IP);

    std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(RutaFinal, "r"), _pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}
