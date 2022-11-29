#pragma once
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <sstream>
#include <fstream>
#include "pretty_out.hpp"

#include <Windows.h>
#include <TlHelp32.h>

#include <wintrust.h>
#include <softpub.h>
#include <imagehlp.h>

#include "pe_signature_verifier.h"

// Link with the Wintrust.lib file.
#pragma comment (lib, "wintrust")

std::string getName(DWORD processID);
BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile);
std::string is_packed(std::string file_name);
std::string getRWX(DWORD processId);
std::string isRWX(DWORD processId);
void process_page(DWORD pid);

void main_page();