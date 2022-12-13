#define _CRT_SECURE_NO_WARNINGS
#include "explorer.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <time.h>
#include "pe_lib/pe_bliss.h"
#include "pe_lib/entropy.h"
#define BUSIZ 0x50000


using namespace pe_bliss;


std::vector<std::pair<std::string, std::size_t>> get_file_section(std::string path) {
    std::ifstream pe_file(path, std::ios::in | std::ios::binary);
    std::vector<std::pair<std::string, std::size_t>> res;

    if (!pe_file)
        return res;

    pe_base image(pe_factory::create_pe(pe_file));
    const section_list sections = image.get_image_sections();
    for (int i = 0; i < sections.size(); i++)
    {
        std::size_t result = std::hash<std::string>()(sections[i].get_raw_data());
        res.push_back(std::make_pair(sections[i].get_name(), result));
    }

    return res;
}


std::vector<std::pair<std::string, std::size_t>> get_process_section(DWORD pid) {

    std::vector<std::pair<std::string, std::size_t>> res;

    char buf[BUSIZ] = { 0 };
    char* tmpbuf = 0;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (hProcess == 0)
        return res;
    HMODULE hMods[2048];
    DWORD cbNeeded;
    unsigned int i;
    EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL);

    //std::cout << modules;
    MODULEINFO info;
    GetModuleInformation(hProcess, hMods[0], &info, sizeof(info));
    LPCVOID baseAddress = (LPVOID)info.lpBaseOfDll;

    ReadProcessMemory(hProcess, baseAddress, &buf, sizeof(buf), 0);

    PIMAGE_DOS_HEADER dhead = (PIMAGE_DOS_HEADER)&buf;
    LPVOID NEWAddress = (LPVOID)((DWORD_PTR)baseAddress + dhead->e_lfanew);
    ReadProcessMemory(hProcess, NEWAddress, &buf, sizeof(buf), 0);
    PIMAGE_NT_HEADERS64 nthead = (PIMAGE_NT_HEADERS64)&buf;
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(nthead);
    for (WORD i = 0; i < nthead->FileHeader.NumberOfSections; i++) {
        int total_size = Section->SizeOfRawData;
        NEWAddress = (LPVOID)((DWORD_PTR)baseAddress + Section->VirtualAddress);
        tmpbuf = (char*)realloc(0, Section->SizeOfRawData);
        memset(tmpbuf, 0, Section->SizeOfRawData);
        ReadProcessMemory(hProcess, NEWAddress, tmpbuf, Section->SizeOfRawData, 0);
        std::string section = std::string(tmpbuf, Section->SizeOfRawData);

        std::size_t result = std::hash<std::string>()(section);
        res.push_back(std::make_pair((char*)Section->Name, result));
        Section++;
    }
    free(tmpbuf);
    return res;
}

void get_section(DWORD pid, std::string path) {
    VariadicTable<std::string, std::size_t, std::string, std::size_t>
        vt({ "File Section", "Hash", "Process Section", "Hash" });

    std::vector<std::pair<std::string, std::size_t>> f_section = get_file_section(path);
    std::vector<std::pair<std::string, std::size_t>> p_section = get_process_section(pid);


    for (int i = 0, j = 0; i < p_section.size() and j < f_section.size(); j++, i++) {
        vt.addRow(f_section[i].first, f_section[i].second, p_section[j].first, p_section[j].second);
    }
    vt.print(std::cout);
}

std::string is_eq(DWORD pid, std::string path) {
    std::vector<std::pair<std::string, std::size_t>> f_section = get_file_section(path);
    std::vector<std::pair<std::string, std::size_t>> p_section = get_process_section(pid);

    if (p_section.size() == 0 || f_section.size() == 0)
        return "";

    if (f_section[0].first != p_section[0].first || f_section[0].second != p_section[0].second)
        return "True";

    return "False";
}

