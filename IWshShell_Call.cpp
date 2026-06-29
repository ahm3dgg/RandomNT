// https://www.vbsedit.com/html/6f28899c-d653-4555-8a59-49640b0e32ea.asp

#include <Windows.h>
#include <cstdio>

#define rcast reinterpret_cast

// IDA is the best.
typedef HRESULT(__stdcall *_Run)(
    void *_this,
    BSTR command,
    tagVARIANT *initWindowStyle,
    tagVARIANT *bWaitOnReturn,
    int *pReturn);

int Error(HRESULT hr)
{
    printf("HRESULT=%08X\n", hr);
    return 1;
}

int main()
{
    HRESULT hr;
    CLSID clsid;
    IID iid;

    hr = ::CoInitialize(nullptr);
    if (FAILED(hr))
        return Error(hr);

    // CLSID_Windows Script Host Shell Object
    hr = ::CLSIDFromString(L"{F935DC22-1CF0-11D0-ADB9-00C04FD58A0B}", &clsid);
    if (FAILED(hr))
        return Error(hr);

    // IID_IWshShell
    hr = ::IIDFromString(L"{F935DC21-1CF0-11D0-ADB9-00C04FD58A0B}", &iid);
    if (FAILED(hr))
        return Error(hr);

    size_t **iff = nullptr;
    hr = ::CoCreateInstance(clsid, nullptr, CLSCTX_ALL, iid, rcast<LPVOID *>(&iff));
    if (FAILED(hr))
        return Error(hr);

    size_t *vptr = *iff;
    printf("vtable -> %p\n", vptr);

    auto Run = rcast<_Run>(vptr[9]);
    printf("Run Method at: %p\n", Run);

    BSTR Command = ::SysAllocString(L"notepad.exe");

    tagVARIANT intWindowStyle;
    tagVARIANT bWaitOnReturn;

    ::VariantInit(&intWindowStyle);
    ::VariantInit(&bWaitOnReturn);

    intWindowStyle.vt = VT_INT;
    intWindowStyle.intVal = 1; // Activates and displays a window.

    bWaitOnReturn.vt = VT_BOOL;
    bWaitOnReturn.boolVal = 0; // Run method returns immediately after starting the program

    int Return = 0;
    printf("Return -> %08X\n", Run(iff, Command, &intWindowStyle, &bWaitOnReturn, &Return));
}