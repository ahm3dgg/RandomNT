#include <phnt_windows.h>
#include <phnt.h>
#include <cstdio>

#pragma comment(lib, "ntdll.lib")

#define NTCHECK(a)                 \
    {                              \
        Status = (a);              \
        if (!NT_SUCCESS(Status))   \
        {                          \
            ReportNTError(Status); \
            return Status;         \
        }                          \
    }

void ReportNTError(NTSTATUS Status)
{
    LPWSTR Message = nullptr;
    HMODULE NTDLLBase = GetModuleHandleW(L"ntdll.dll");

    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE,
        NTDLLBase,
        Status,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&Message,
        0,
        NULL);

    if (Message)
    {
        wprintf(L"Status 0x%X: %s\n", Status, Message);
        LocalFree(Message);
    }
    else
    {
        wprintf(L"Unknown Status code: 0x%X\n", Status);
    }
}

int main()
{
    HANDLE FileHandle = NULL;
    OBJECT_ATTRIBUTES ObjectAttrs;
    UNICODE_STRING FileName;
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatusBlock;

    NTCHECK(
        RtlDosPathNameToNtPathName_U_WithStatus(
            NtCurrentPeb()->ProcessParameters->ImagePathName.Buffer,
            &FileName,
            nullptr,
            nullptr));

    InitializeObjectAttributes(&ObjectAttrs, &FileName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    NTCHECK(
        NtOpenFile(
            &FileHandle,
            DELETE | SYNCHRONIZE,
            &ObjectAttrs,
            &IoStatusBlock,
            0,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE));

    WCHAR NewName[] = L":GG";
    PFILE_RENAME_INFORMATION FileRenameInfo = nullptr;
    SIZE_T FileRenameInfoSZ = sizeof(FILE_RENAME_INFORMATION) + sizeof(NewName);

    NTCHECK(
        NtAllocateVirtualMemory(
            GetCurrentProcess(),
            (PVOID *)&FileRenameInfo,
            0,
            &FileRenameInfoSZ,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE))

    FileRenameInfo->FileNameLength = sizeof(NewName) - sizeof(WCHAR);
    RtlCopyMemory(FileRenameInfo->FileName, NewName, sizeof(NewName));

    NTCHECK(
        NtSetInformationFile(
            FileHandle,
            &IoStatusBlock,
            FileRenameInfo,
            sizeof(FILE_RENAME_INFORMATION) + sizeof(NewName),
            FileRenameInformation));

    NTCHECK(
        NtFreeVirtualMemory(
            GetCurrentProcess(),
            (PVOID *)&FileRenameInfo,
            &FileRenameInfoSZ,
            MEM_RELEASE));

    NTCHECK(NtClose(FileHandle));

    NTCHECK(
        NtOpenFile(
            &FileHandle,
            DELETE | SYNCHRONIZE,
            &ObjectAttrs,
            &IoStatusBlock,
            0,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE));

    FILE_DISPOSITION_INFO_EX FileDisp = {};
    FileDisp.Flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;

    NTCHECK(
        NtSetInformationFile(
            FileHandle,
            &IoStatusBlock,
            &FileDisp,
            sizeof(FILE_DISPOSITION_INFO_EX),
            FileDispositionInformationEx));

    NTCHECK(NtClose(FileHandle));

    RtlFreeUnicodeString(&FileName);

    puts("Self-deletion triggered successfully!");
    getchar();
    return 0;
}