#include "explorer.h"

std::string getName(DWORD processID)
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (NULL != hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
            GetModuleFileNameEx(hProcess, hMod, szProcessName,
                sizeof(szProcessName) / sizeof(TCHAR));
    }

    CloseHandle(hProcess);

    std::wstring wName = szProcessName;
    std::string sName(wName.begin(), wName.end());
    return sName;
}