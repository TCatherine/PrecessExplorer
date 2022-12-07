#include "explorer.h"


void show_cert(std::string path) {
    DWORD lRetVal = PeSignatureVerifier::CheckFileSignature(std::wstring(path.begin(), path.end()));
    std::string ver = "unsigned";
    if (lRetVal == ERROR_SUCCESS)
        ver = "signed";
    std::cout << "File is " << ver << std::endl;
    if (path != "<unknown>") {
        PeSignatureVerifier::SignerInfoPtr cert;
        DWORD r = PeSignatureVerifier::GetCertificateInfo(std::wstring(path.begin(), path.end()), cert);
        if (r == ERROR_SUCCESS)
        cert->PrintCertificateInfo();
    }
}

void show_net(DWORD pid) {
    NetStatistic info;
    info.num = 0;

    get_tcp_info(pid, info);
    get_udp_info(pid);
    if (info.num)
        printf(" PR %-23s %-23s %-12s %-12s %s\n", "SRC ADDR", "DST ADDR", "State", "Owner PID", "Mode");
    else
        std::cout << "Network address doesn't found!" << std::endl;
    for (int i = 0; i < info.num; i++)
    {
        if (!info.table[i].remoteInfo.empty() && info.table[i].remoteInfo != "0.0.0.0:0") {
            std::string ip = info.table[i].remoteInfo.substr(0, info.table[i].remoteInfo.find_last_of(":"));
            std::cout << GetIpInfo(ip.c_str()) << std::endl;
        }
    }
}

void show_mitre_attack(std::string path) {
    std::string cmd = "C:\\capa.exe " + path;
    char   psBuffer[1025];
    FILE* pPipe;

    if ((pPipe = _popen(cmd.c_str(), "rt")) == NULL)
        std::cout << "Сould not find signatures" << std::endl;
    else {
        for (int i = 0; i < 12 && fgets(psBuffer, 1024, pPipe); i++);
        std::string finish_string = "+------------------------+------------------------------------------------------------------------------------+\n";
        while (fgets(psBuffer, 1024, pPipe))
        {
            if (finish_string == psBuffer) {
                std::cout << psBuffer;
                break;
            }

            std::cout << psBuffer;
        }
    }
    std::cout << std::endl;

}
void show_process(DWORD pid) {
    system("cls");
    std::string path = getName(pid);
    std::cout << "----------------------------------------------------------------------------------------------------" << std::endl;
    std::cout << "FILE: " << path << " ( " << pid << " )" << std::endl;
    std::cout << "----------------------------------------------------------------------------------------------------" << std::endl;
    show_cert(path);
    std::cout << "----------------------------------------------------------------------------------------------------" << std::endl;
    std::cout << is_packed(path) << std::endl;
    std::cout << "----------------------------------------------------------------------------------------------------" << std::endl;
    std::cout << getRWX(pid) << std::endl;
    std::cout << "----------------------------------------------------------------------------------------------------" << std::endl;
    show_net(pid);
    std::cout << "----------------------------------------------------------------------------------------------------" << std::endl;
    //show_mitre_attack(path);
    get_section(pid, path);

}

void process_page(DWORD pid) {
    while (1) {
        show_process(pid);
        std::cout << "------------------------------------" << std::endl;
        std::cout << "| f - refresh | otherwise to return |" << std::endl;
        std::cout << "------------------------------------" << std::endl;
        std::cout << "> ";

        std::string command;
        std::cin >> command;
        if (command == "f") {
            show_process(pid);
            continue;
        }

        return;
    }
}