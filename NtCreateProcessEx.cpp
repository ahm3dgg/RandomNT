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

int wmain(int ArgCount, wchar_t *Args[])
{
    NTSTATUS Status = {};
    PCWSTR ExePath = {};
    UNICODE_STRING NtExePath = {};
    PWSTR FileName = {};
    HANDLE FileHandle = {};
    HANDLE SectionHandle = {};
    HANDLE ProcessHandle = {};
    UNICODE_STRING ImagePathName = {};
    UNICODE_STRING DllPath = {};
    OBJECT_ATTRIBUTES ObjectAttrs = {};
    IO_STATUS_BLOCK IoStatusBlock = {};
    ULONG RLength = {};
    SIZE_T BytesWritten = {};
    PROCESS_BASIC_INFORMATION ProcessInfo = {};
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters = {};
    SECTION_IMAGE_INFORMATION ImageInfo = {};
    HANDLE ThreadHandle = {};
    WCHAR ImageNameBuffer[MAX_PATH];
    UNICODE_STRING ImageName;
    UNICODE_STRING CurrentDir;
    SIZE_T ProcessParametersSize;
    PVOID RemoteProcessParameters;
    SIZE_T RemoteProcessParametersSize;

    if (ArgCount != 2)
    {
        wprintf(L"NtCreateProcessEx.exe <exepath>\n");
        return 1;
    }

    ExePath = Args[1];

    NTCHECK(RtlDosPathNameToNtPathName_U_WithStatus(
        ExePath,
        &NtExePath,
        &FileName,
        nullptr));

    InitializeObjectAttributes(&ObjectAttrs, &NtExePath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    NTCHECK(NtOpenFile(
        &FileHandle,
        GENERIC_READ | GENERIC_EXECUTE | SYNCHRONIZE,
        &ObjectAttrs,
        &IoStatusBlock,
        FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT));

    NTCHECK(NtCreateSection(
        &SectionHandle,
        GENERIC_ALL,
        nullptr,
        nullptr,
        PAGE_EXECUTE,
        SEC_IMAGE,
        FileHandle));

    NTCHECK(NtCreateProcessEx(
        &ProcessHandle,
        GENERIC_ALL,
        nullptr,
        GetCurrentProcess(),
        PROCESS_CREATE_FLAGS_NONE,
        SectionHandle,
        0,
        0,
        0));

    NTCHECK(NtQueryInformationProcess(
        ProcessHandle,
        ProcessBasicInformation,
        (PVOID)&ProcessInfo,
        sizeof(PROCESS_BASIC_INFORMATION),
        &RLength));

    ImageName.Buffer = ImageNameBuffer;
    ImageName.MaximumLength = sizeof(ImageNameBuffer);
    ImageName.Length = (USHORT)RtlGetFullPathName_U(Args[1], ImageName.MaximumLength, &ImageNameBuffer[0], NULL);

    RtlInitUnicodeString(&CurrentDir, ((PKUSER_SHARED_DATA)USER_SHARED_DATA)->NtSystemRoot);

    NTCHECK(RtlCreateProcessParametersEx(
        &ProcessParameters,
        &ImageName,
        &CurrentDir,
        &CurrentDir,
        &ImageName,
        RtlGetCurrentPeb()->ProcessParameters->Environment,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        RTL_USER_PROC_PARAMS_NORMALIZED));

    ProcessParametersSize = ProcessParameters->MaximumLength + ProcessParameters->EnvironmentSize;
    RemoteProcessParameters = nullptr;
    RemoteProcessParametersSize = ProcessParametersSize;

    NTCHECK(NtAllocateVirtualMemory(
        ProcessHandle,
        &RemoteProcessParameters,
        0,
        &RemoteProcessParametersSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE));

    RtlDeNormalizeProcessParams(ProcessParameters);
    ProcessParameters->Environment = (PVOID)((SIZE_T)ProcessParameters->Environment + ((SIZE_T)RemoteProcessParameters - (SIZE_T)ProcessParameters));

    NTCHECK(NtWriteVirtualMemory(
        ProcessHandle,
        RemoteProcessParameters,
        ProcessParameters,
        ProcessParametersSize,
        nullptr));

    NTCHECK(NtWriteVirtualMemory(
        ProcessHandle,
        (PVOID)&ProcessInfo.PebBaseAddress->ProcessParameters,
        &RemoteProcessParameters,
        sizeof(RemoteProcessParameters),
        nullptr));

    NTCHECK(RtlDestroyProcessParameters(ProcessParameters));

    NTCHECK(NtQueryInformationProcess(ProcessHandle, ProcessImageInformation, &ImageInfo, sizeof(ImageInfo), nullptr));

    NTCHECK(NtCreateThreadEx(
        &ThreadHandle,
        THREAD_ALL_ACCESS,
        nullptr,
        ProcessHandle,
        (PUSER_THREAD_START_ROUTINE)ImageInfo.TransferAddress,
        nullptr,
        0,
        ImageInfo.ZeroBits,
        ImageInfo.CommittedStackSize,
        ImageInfo.MaximumStackSize,
        nullptr));
}