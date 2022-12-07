#pragma once
#include <Windows.h>
#include <iphlpapi.h>
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "WS2_32.lib")

struct NetConnet {
    const char protocol[4];
    std::string localInfo;
    std::string remoteInfo;
    std::string state;
    //DWORD pid;
};

struct NetStatistic {
    int num;
    std::vector <NetConnet> table;

};

DWORD  get_tcp_info(DWORD pid, struct NetStatistic&);
struct NetStatistic  get_udp_info(DWORD pid);
int GetNetstat(DWORD pid);
std::string is_net(DWORD);