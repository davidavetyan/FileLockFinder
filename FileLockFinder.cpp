#include <cstdio>
#include <new>
#include <malloc.h>

// Nt includes
#include <phnt_windows.h>
#include <phnt.h>

// Defines
#define FILE_SHARE_VALID_FLAGS 0x00000007 // wdm.h


// Forward declarations
NTSTATUS PrintProcessesUsingFile(PCWSTR pszFile);
NTSTATUS PrintProcessesUsingFile(POBJECT_ATTRIBUTES poa);
NTSTATUS PrintProcessesUsingFile(HANDLE hFile);
NTSTATUS PrintProcessesUsingFile(PFILE_PROCESS_IDS_USING_FILE_INFORMATION ppiufi);


// Main entry
int wmain(int argc, WCHAR **argv)
{
    if (argc != 2)
    {
        wprintf(L"Usage: FileLockFinder <file_name>\n");
        return 0;
    }

    PCWSTR pszFile = argv[1];

    wprintf(L"Showing results for: %s\n\n", pszFile);

    NTSTATUS nStatus = PrintProcessesUsingFile(pszFile);
    if (nStatus != STATUS_SUCCESS)
        wprintf(L"Unable to load information for the specified input.\n"
                "Error code: %#lx\n",
                nStatus);

    return 0;
}


NTSTATUS PrintProcessesUsingFile(PCWSTR pszFile)
{
    UNICODE_STRING ObjectName;
    NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(pszFile, &ObjectName, 0, 0);
    if (0 <= status)
    {
        OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName };
        status = PrintProcessesUsingFile(&oa);
        RtlFreeUnicodeString(&ObjectName);
    }

    return status;
}

NTSTATUS PrintProcessesUsingFile(POBJECT_ATTRIBUTES poa)
{
    IO_STATUS_BLOCK iosb;
    HANDLE hFile;
    NTSTATUS status = NtOpenFile(&hFile, FILE_READ_ATTRIBUTES, poa, &iosb, FILE_SHARE_VALID_FLAGS, 0);
    if (0 <= status)
    {
        status = PrintProcessesUsingFile(hFile);
        NtClose(hFile);
    }

    return status;
}

NTSTATUS PrintProcessesUsingFile(HANDLE hFile)
{
    NTSTATUS status;
    IO_STATUS_BLOCK iosb;

    ULONG cb = 0, rcb = FIELD_OFFSET(FILE_PROCESS_IDS_USING_FILE_INFORMATION, ProcessIdList[64]);

    union {
        PVOID buf;
        PFILE_PROCESS_IDS_USING_FILE_INFORMATION ppiufi;
    };

    PVOID pStack = alloca(0);

    do
    {
        if (cb < rcb)
        {
            cb = RtlPointerToOffset(buf = alloca(rcb - cb), pStack);
        }

        status =
            NtQueryInformationFile(hFile, &iosb, ppiufi, cb, FileProcessIdsUsingFileInformation);
        if (0 <= status)
        {
            if (ppiufi->NumberOfProcessIdsInList)
            {
                PrintProcessesUsingFile(ppiufi);
            }
        }

        rcb = (ULONG)iosb.Information;
    }
    while (status == STATUS_INFO_LENGTH_MISMATCH);

    return status;
}

NTSTATUS PrintProcessesUsingFile(PFILE_PROCESS_IDS_USING_FILE_INFORMATION ppiufi)
{
    wprintf(L"%s\n", L"==================================================");
    wprintf(L"%-15s %s\n", L"PID", L"Name");
    wprintf(L"%s\n", L"--------------------------------------------------");

    NTSTATUS status;
    ULONG cb = 0x8000;

    do
    {
        status = STATUS_INSUFFICIENT_RESOURCES;

        if (PVOID buf = new (std::nothrow) BYTE[cb])
        {
            if (0 <= (status = NtQuerySystemInformation(SystemProcessInformation, buf, cb, &cb)))
            {
                union {
                    PVOID pv;
                    PBYTE pb;
                    PSYSTEM_PROCESS_INFORMATION pspi;
                };

                pv = buf;
                ULONG NextEntryOffset = 0;

                do
                {
                    pb += NextEntryOffset;

                    ULONG NumberOfProcessIdsInList = ppiufi->NumberOfProcessIdsInList;

                    PULONG_PTR ProcessIdList = ppiufi->ProcessIdList;
                    do
                    {
                        if (*ProcessIdList++ == (ULONG_PTR)pspi->UniqueProcessId)
                        {
                            wprintf(L"%-15u %wZ\n", pspi->UniqueProcessId, &pspi->ImageName);
                            break;
                        }
                    }
                    while (--NumberOfProcessIdsInList);
                }
                while ((NextEntryOffset = pspi->NextEntryOffset));
            }

            delete[] buf;
        }
    }
    while (status == STATUS_INFO_LENGTH_MISMATCH);

    wprintf(L"%s\n", L"==================================================");

    return status;
}


#if 0 // Restart Manager API
void PrintProcessesUsingFile_RM(PCWSTR pszFile)
{
    DWORD dwSession;
    WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1] = { 0 };
    DWORD dwError = RmStartSession(&dwSession, 0, szSessionKey);
    if (dwError == ERROR_SUCCESS)
    {
        dwError = RmRegisterResources(dwSession, 1, &pszFile, 0, nullptr, 0, nullptr);

        if (dwError == ERROR_SUCCESS)
        {
            DWORD dwReason;
            UINT i;
            UINT nProcInfoNeeded;
            UINT nProcInfo = 10;
            RM_PROCESS_INFO rgpi[10];
            dwError = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, rgpi, &dwReason);
            if (dwError == ERROR_SUCCESS)
            {
                for (i = 0; i < nProcInfo; i++)
                {
                    wprintf(L"%d.ApplicationType = %d\n", i, rgpi[i].ApplicationType);
                    wprintf(L"%d.strAppName = %ls\n", i, rgpi[i].strAppName);
                    wprintf(L"%d.Process.dwProcessId = %d\n", i, rgpi[i].Process.dwProcessId);

                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false,
                                                  rgpi[i].Process.dwProcessId);
                    if (hProcess)
                    {
                        FILETIME ftCreate, ftExit, ftKernel, ftUser;
                        if (GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser) &&
                            CompareFileTime(&rgpi[i].Process.ProcessStartTime, &ftCreate) == 0)
                        {
                            WCHAR sz[MAX_PATH];
                            DWORD cch = MAX_PATH;
                            if (QueryFullProcessImageNameW(hProcess, 0, sz, &cch) &&
                                cch <= MAX_PATH)
                            {
                                wprintf(L"  = %ls\n", sz);
                            }
                        }
                        CloseHandle(hProcess);
                    }
                }
            }
        }
        RmEndSession(dwSession);
    }

    if (dwError != ERROR_SUCCESS)
        wprintf(L"Error code: %#lx\nExiting...\n", dwError);
}
#endif