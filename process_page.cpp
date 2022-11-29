#include "explorer.h"


void show_cert(std::string path) {
    DWORD lRetVal = PeSignatureVerifier::CheckFileSignature(std::wstring(path.begin(), path.end()));
    std::string ver = "unsigned";
    if (lRetVal == ERROR_SUCCESS)
        ver = "signed";
    if (path != "<unknown>") {
        PeSignatureVerifier::SignerInfoPtr cert;
        PeSignatureVerifier::GetCertificateInfo(std::wstring(path.begin(), path.end()), cert);
        std::cout << "File is " << ver << std::endl;
        cert->PrintCertificateInfo();
    }
}

void show_process(DWORD pid) {
    system("cls");
    std::string path = getName(pid);
    std::cout << "-------------------------------------------------------------" << std::endl;
    std::cout << "FILE: " << path << " ( " << pid << " )" << std::endl;
    std::cout << "------------------------------------------------------------" << std::endl;
    show_cert(path);
    std::cout << "------------------------------------------------------------" << std::endl;
    std::cout << is_packed(path) << std::endl;
    std::cout << "------------------------------------------------------------" << std::endl;
    std::cout << getRWX(pid) << std::endl;
    std::cout << "------------------------------------------------------------" << std::endl;

}

void process_page(DWORD pid) {
    while (1) {
        show_process(pid);
        std::cout << "------------------------------------" << std::endl;
        std::cout << "| r - refresh | otherwise to return |" << std::endl;
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