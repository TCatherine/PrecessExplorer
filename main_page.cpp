#include "explorer.h"

void show_main() {
    VariadicTable<std::string, DWORD, std::string, std::string, std::string>
        vt({ "Name", "PID", "Verified", "Packed", "RWX" });
    PeSignatureVerifier checker = PeSignatureVerifier();

    DWORD aProcesses[1024], cbNeeded, cProcesses;

    unsigned int i;

    EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded);

    cProcesses = cbNeeded / sizeof(DWORD);
    for (i = 0; i < cProcesses && i < 10; i++)
        if (aProcesses[i] != 0)
        {
            std::string path = getName(aProcesses[i]);
            std::string name = path.substr(path.find_last_of("\\") + 1);

            DWORD lRetVal = PeSignatureVerifier::CheckFileSignature(std::wstring(path.begin(), path.end()));
            std::string ver = "Unsigned";
            if (lRetVal == ERROR_SUCCESS)
                ver = "Signed";

            std::string packed_res = is_packed(path);
            std::string rwx_res = isRWX(aProcesses[i]);
            vt.addRow(name, aProcesses[i], ver, packed_res, rwx_res);
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
