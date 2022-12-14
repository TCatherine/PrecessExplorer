#define _CRT_SECURE_NO_WARNINGS

#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <string>
#include <array>
#include "json.hpp"
#include <winsock2.h>
#include <windows.h>
#include <curl/curl.h>
#include <regex>


using json = nlohmann::json;

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

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}


std::string get_score(std::string IP = "31.134.188.51") {
    CURL* curl;
    std::string readBuffer;
    std::string key = "ed0b0c022abc6bc460128d5b2901b2c0d9fc46ecfd94d9e410d78bca69050f179c3b908ed03ea2ab";
    std::string link = "https://api.abuseipdb.com/api/v2/check?ipAddress=";
    link += IP;

    struct curl_slist* list = NULL;
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, link.c_str());
        std::string key_header = "Key: " + key;
        list = curl_slist_append(list, "Accept: application/json");
        list = curl_slist_append(list, key_header.c_str());

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        const std::regex r("\"abuseConfidenceScore\":([0-9])+");
        std::smatch m;

        if (std::regex_search(readBuffer, m, r)) {
            return m[1];
        }

        return "";
    }
}