#include "explorer.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#define BUSIZ 0x500
#define MAXREAD 0x400

 FILE* infile = NULL;
void hexdump(int bpos, unsigned char* inbuf) {
    memset(inbuf, 0, BUSIZ);
    fseek(infile, bpos, SEEK_SET);
    size_t siz = fread_s(inbuf, BUSIZ, 1, MAXREAD, infile);

}

void hashdump(int bpos, char* inbuf, int size) {
    memset(inbuf, 0, BUSIZ);
    fseek(infile, bpos, SEEK_SET);
    size_t siz = fread_s(inbuf, BUSIZ, 1, MAXREAD, infile);
    std::string section = inbuf;
    std::size_t result = std::hash<std::string>()(section);
    std::cout << "File hash: " << result << std::endl;
}

void get_section_file(std::string path) {
    unsigned char buf[BUSIZ] = { 0 };
    char tmpbuf[BUSIZ] = { 0 };
    errno_t err = fopen_s(&infile, path.c_str(), "rb");
    if (err == 0 && infile != NULL) {
        hexdump(0, buf);
        PIMAGE_DOS_HEADER dhead = (PIMAGE_DOS_HEADER)&buf;
        hexdump(dhead->e_lfanew, buf);
        PIMAGE_NT_HEADERS64 nthead = (PIMAGE_NT_HEADERS64)&buf;
        PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(nthead);
        for (WORD i = 0; i < nthead->FileHeader.NumberOfSections; i++) {
            printf("%-8s\t%x\t%x\t%x\n", Section->Name, Section->VirtualAddress,
                Section->PointerToRawData, Section->SizeOfRawData);
            hashdump(Section->VirtualAddress, tmpbuf, Section->SizeOfRawData);
            Section++;
        }
    }
}

void get_section_process(DWORD pid) {
    LPCVOID Address = (LPCVOID)0x012d5678;

    unsigned char buf[BUSIZ];
    char tmpbuf[BUSIZ] = { 0 };
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, 0, pid);

    ReadProcessMemory(hProcess, Address, &buf, sizeof(buf), 0);

    hexdump(0, buf);
    PIMAGE_DOS_HEADER dhead = (PIMAGE_DOS_HEADER)&buf;
    hexdump(dhead->e_lfanew, buf);
    PIMAGE_NT_HEADERS64 nthead = (PIMAGE_NT_HEADERS64)&buf;
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(nthead);
    for (WORD i = 0; i < nthead->FileHeader.NumberOfSections; i++) {
        printf("%-8s\t%x\t%x\t%x\n", Section->Name, Section->VirtualAddress,
            Section->PointerToRawData, Section->SizeOfRawData);
        hashdump(Section->VirtualAddress, tmpbuf, Section->SizeOfRawData);
        Section++;
    }
}

void get_section(DWORD pid, std::string path) {
    VariadicTable<std::string, std::size_t, std::string, std::size_t>
        vt({ "File Section", "Hash", "Process Section", "Hash" });

    unsigned char buf[BUSIZ] = { 0 };
    char tmpbuf[BUSIZ] = { 0 };
    errno_t err = fopen_s(&infile, path.c_str(), "rb");

    std::vector<std::string> file_section;
    std::vector<std::size_t> file_hash;
    if (err == 0 && infile != NULL) {
        hexdump(0, buf);
        PIMAGE_DOS_HEADER dhead = (PIMAGE_DOS_HEADER)&buf;
        hexdump(dhead->e_lfanew, buf);
        PIMAGE_NT_HEADERS64 nthead = (PIMAGE_NT_HEADERS64)&buf;
        PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(nthead);
        for (WORD i = 0; i < nthead->FileHeader.NumberOfSections; i++) {
            file_section.push_back((char*)Section->Name);
            //printf("%-8s\t%x\t%x\t%x\n", Section->Name, Section->VirtualAddress,
            //    Section->PointerToRawData, Section->SizeOfRawData);
            memset(tmpbuf, 0, BUSIZ);
            fseek(infile, Section->PointerToRawData, SEEK_SET);
            size_t siz = fread_s(tmpbuf, BUSIZ, 1, MAXREAD, infile);
            std::string section = tmpbuf;
            std::size_t result = std::hash<std::string>()(section);
            Section++;
            file_hash.push_back(result);
        }
    }
    memset(buf, 0, BUSIZ);
    LPCVOID Address = (LPCVOID)0x012d5678;
    hexdump(0, buf);
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, 0, pid);
    ReadProcessMemory(hProcess, Address, &buf, sizeof(buf), 0);

    std::vector<std::string> pr_section;
    std::vector<std::size_t> pr_hash;
    if (err == 0 && infile != NULL) {
        hexdump(0, buf);
        PIMAGE_DOS_HEADER dhead = (PIMAGE_DOS_HEADER)&buf;
        hexdump(dhead->e_lfanew, buf);
        PIMAGE_NT_HEADERS64 nthead = (PIMAGE_NT_HEADERS64)&buf;
        PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(nthead);
        for (WORD i = 0; i < nthead->FileHeader.NumberOfSections; i++) {
            pr_section.push_back((char*)Section->Name);
            //printf("%-8s\t%x\t%x\t%x\n", Section->Name, Section->VirtualAddress,
            //    Section->PointerToRawData, Section->SizeOfRawData);
            memset(tmpbuf, 0, BUSIZ);
            fseek(infile, Section->PointerToRawData, SEEK_SET);
            size_t siz = fread_s(tmpbuf, BUSIZ, 1, MAXREAD, infile);
            std::string section = tmpbuf;
            std::size_t result = std::hash<std::string>()(section);
            Section++;
            pr_hash.push_back(result);
        }
    }

    for (int i = 0, j = 0; i < file_section.size() and j < file_section.size(); j++, i++) {
        vt.addRow(file_section[i], file_hash[i], pr_section[j], pr_hash[j]);
    }
    vt.print(std::cout);
}

