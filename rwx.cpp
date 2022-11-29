#include "explorer.h"

std::string getRWX(DWORD processId)
{
	MEMORY_BASIC_INFORMATION mbi = {};
	LPVOID offset = 0;
	std::string res = "";
	
	HANDLE process = OpenProcess(MAXIMUM_ALLOWED, false, processId);
	if (process)
	{
		while (VirtualQueryEx(process, offset, &mbi, sizeof(mbi)))
		{
			offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
			if (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE)
			{
				std::stringstream stream;
				stream << std::hex << mbi.BaseAddress;
				res.append("RWX:	0x"+stream.str()+"\n");
			}
		}
		offset = 0;
	}
	CloseHandle(process);

	if (res == "")
		res.append("Sections available for writing and execution were not found!");
	return res;
}

std::string isRWX(DWORD processId) {
	MEMORY_BASIC_INFORMATION mbi = {};
	LPVOID offset = 0;

	HANDLE process = OpenProcess(MAXIMUM_ALLOWED, false, processId);
	if (process)
	{
		while (VirtualQueryEx(process, offset, &mbi, sizeof(mbi)))
		{
			offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
			if (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE)
			{
				return "Detect";
			}
		}
		offset = 0;
	}
	CloseHandle(process);

	//return res;
	return "Clear";

}