#include "explorer.h"

static ULARGE_INTEGER lastCPU, lastSysCPU, lastUserCPU;
static int numProcessors;
static HANDLE self;

void init(HANDLE hProcess) {
    SYSTEM_INFO sysInfo;
    FILETIME ftime, fsys, fuser;

    GetSystemInfo(&sysInfo);
    numProcessors = sysInfo.dwNumberOfProcessors;

    GetSystemTimeAsFileTime(&ftime);
    memcpy(&lastCPU, &ftime, sizeof(FILETIME));

    GetProcessTimes(hProcess, &ftime, &ftime, &fsys, &fuser);
    memcpy(&lastSysCPU, &fsys, sizeof(FILETIME));
    memcpy(&lastUserCPU, &fuser, sizeof(FILETIME));
}

void show_main() {
    VariadicTable<std::string, DWORD, std::string, std::string, std::string, std::string, std::string, std::string >
        vt({ "Name", "PID", "Verified", "Packed", "RWX", "Net", "Modified", "Malware"});
    PeSignatureVerifier checker = PeSignatureVerifier();

    DWORD aProcesses[1024], cbNeeded, cProcesses;

    unsigned int i;

    EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded);

    cProcesses = cbNeeded / sizeof(DWORD);
    std::vector<std::pair<std::size_t, DWORD>> pr;

    for (i = 0; i < cProcesses; i++) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, aProcesses[i]);
        if (hProcess == 0)
            continue;

        /*PROCESS_MEMORY_COUNTERS memCounter;
        BOOL result = GetProcessMemoryInfo(hProcess,
            &memCounter,
            sizeof(memCounter));

        std::cout << aProcesses[i] << " " << memCounter.PagefileUsage << std::endl;*/
        PROCESS_MEMORY_COUNTERS_EX pmc;
        GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));
        SIZE_T mem = pmc.WorkingSetSize;

        pr.push_back(std::make_pair(mem, aProcesses[i]));
    }

    std::sort(pr.begin(), pr.end());

    for (int i = pr.size() - 1, j = 0; i >= 0 && j < 20; i--, j++)
        if (pr[i].second != 0)
        {
            int is_malware = 0;
            std::string path = getName(pr[i].second);
            std::string name = path.substr(path.find_last_of("\\") + 1);

            DWORD lRetVal = PeSignatureVerifier::CheckFileSignature(std::wstring(path.begin(), path.end()));
            std::string ver = "Signed";
            if (lRetVal != ERROR_SUCCESS) {
                ver = "Unsigned";
                is_malware += 11;
            }

            std::string packed_res = is_packed(path);
            if (packed_res == "Packed")
                is_malware += 1;
            //std::string packed_res = "";

            std::string rwx_res = isRWX(pr[i].second);
            if (rwx_res == "Detect")
                is_malware += 1;

            std::string ip = is_net(pr[i].second);
            if (ip == "True")
                is_malware += 1;

            std::string is_not_eq = is_eq(pr[i].second, path);
            if (is_not_eq == "False") {
                is_malware += 1;
            }

            std::string malware = "";
            if (is_malware >= 14)
                malware = "Yes!!!";
            if (is_malware >= 11)
                malware = "Maybe";


            vt.addRow(name, pr[i].second, ver, packed_res, rwx_res, ip, is_not_eq, malware);
            system("cls");
            vt.print(std::cout);
        }

    system("cls");
    vt.print(std::cout);

}

void main_page() {
    while (1) {
        show_main();
        std::cout << "----------------------------------------------" << std::endl;
        std::cout << "| f - fresh | process pid | otherwise - exit |" << std::endl;
        std::cout << "----------------------------------------------" << std::endl;
        std::cout << "> ";

        std::string command;
        std::cin >> command;
        if (command == "f") {
            show_main();
            continue;
        }

        char* p;
        strtol(command.c_str(), &p, 10);
        if (*p == 0) {
            int pid = atoi(command.c_str());
            process_page(pid);
            continue;
        }

        return;
    }
}
