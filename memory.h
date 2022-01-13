#ifndef MEMORY_H
#define MEMORY_H

#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <codecvt>
#include <locale>
#include <iostream>
#include <comdef.h>

using namespace std;

struct Module { DWORD64 dwBase, dwSize; };

class Memory
{
    HANDLE processHandle;
    DWORD processID;
    Module module;
    DWORD64 signatureAddress;
    DWORD64 globalPointer;

    //TODO
    LPCSTR SigGlobalPTR = "\x48\x8D\x15\x00\x00\x00\x00\x4C\x8B\xC0\xE8\x00\x00\x00\x00\x48\x85\xFF\x48\x89\x1D";
    LPCSTR MaskGlobalPTR = "xxx????xxxx????xxxxxx";

    void getProcess(string processName)
    {
    	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    	PROCESSENTRY32 processEntry;
    	processEntry.dwSize = sizeof(processEntry);

    	do
        {
            _bstr_t exeFile(processEntry.szExeFile);

    		if (_stricmp(exeFile, processName.c_str()) == 0)
            {
                cout << "getProcess: " << exeFile << " : " << processName.c_str() << endl;
    			processID = processEntry.th32ProcessID;
    			CloseHandle(processHandle);

    			processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);
                cout << "Process ID: " << processID << endl;
    		}
        }
    	while (Process32Next(snapshot, &processEntry));
    }

    void getModule(string moduleName)
    {
    	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processID);
    	MODULEENTRY32 moduleEntry;
    	moduleEntry.dwSize = sizeof(moduleEntry);
        cout << "Module entry size: " << moduleEntry.dwSize << endl;

    	do
        {
            _bstr_t moduleEntryName(moduleEntry.szModule);

    		if (_stricmp(moduleEntryName, moduleName.c_str()) == 0)
            {
                cout << "getModule: " << moduleEntryName << " : " << moduleName.c_str() << endl;
    			CloseHandle(snapshot);

    			module = { (DWORD64)moduleEntry.hModule, moduleEntry.modBaseSize };

    		}
    	} while (Module32Next(snapshot, &moduleEntry));

        cout << "Module base: " << (int)module.dwBase << endl;
        cout << "Module size: " << module.dwSize << endl;
    }

    bool memoryCompare(const BYTE* bData, const BYTE* bMask, const char* szMask)
	{
		for (; *szMask; ++szMask, ++bData, ++bMask)
		{
			if (*szMask == 'x' && *bData != *bMask)
			{
				return false;
			}
		}

		return (*szMask == NULL);
	};

    DWORD64 findSignature(DWORD64 start, DWORD64 size, const char* sig, const char* mask)
    {
        cout << "Size: " << size << endl;

        BYTE* data = new BYTE[size];
        SIZE_T bytesRead;

        ReadProcessMemory(processHandle, (LPVOID)start, data, size, &bytesRead);

        for (DWORD64 i = 0; i < size; i++)
        {
            if (memoryCompare((const BYTE*)(data + i), (const BYTE*)sig, mask))
            {
                delete[] data;
                return start + i;
            }
        }

        delete[] data;
        return NULL;
    };

    DWORD64 globalAddress(int index)
    {
        int a = (8 * (index >> 0x12 & 0x3F));
        int b = (8 * (index & 0x3FFFF));
        cout << "Index: " << index << endl;
        cout << "a: " << a << endl;
        cout << "b: " << b << endl;

        cout << "sum: " << (globalPointer + a) << endl;
        return readMemory<DWORD64>(globalPointer + a) + b;
    };

    template <typename DataType>
    DataType readMemory(DWORD64 address)
    {
        DataType valueRead;
        ReadProcessMemory(processHandle, (void*)address, &valueRead, sizeof(DataType), 0);
        return valueRead;
    }

    template <typename DataType>
    void writeMemory(DWORD64 address, DataType value)
    {
        WriteProcessMemory(processHandle, (void*)address, &value, sizeof(DataType), 0);
    }

public:
    bool loaded;

    Memory(const std::string exeName)
    {
        wstring name = wstring(exeName.begin(), exeName.end());

        getProcess(exeName);

        if (processID > 0)
            loaded = true;

        getModule(exeName);

        signatureAddress = findSignature(module.dwBase, module.dwSize, SigGlobalPTR, MaskGlobalPTR);

        cout << "Sig Address: " << signatureAddress << endl;

        globalPointer = signatureAddress + readMemory<int>(signatureAddress + 3) + 7;
    }

    ~Memory()
    {
        CloseHandle(processHandle);
    }

    template <typename DataType>
    DataType getGlobal(int index)
    {
        DWORD64 global = globalAddress(index);
        cout << "Global pointer :" << global << endl;
        return readMemory<DataType>(global);
    };

    template <typename DataType>
    void setGlobal(int index, DataType value)
    {
        writeMemory<DataType>(globalAddress(index), value);
    };
};

#endif //MEMORY_H
