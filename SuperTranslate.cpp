#include <phnt_windows.h>
#include <phnt.h>
#include <cstdio>
#include <unordered_map>

#pragma comment(lib, "ntdll.lib")

std::unordered_map<ULONG_PTR, PPF_PRIVSOURCE_INFO> ProcessInfo;

NTSTATUS SuperfetchQuery(SUPERFETCH_INFORMATION_CLASS SuperfetchClass, PVOID Buffer, ULONG Size, PULONG RequiredSize)
{
    NTSTATUS Status;
    SUPERFETCH_INFORMATION SuperfetchInfo;

    SuperfetchInfo.Version = SUPERFETCH_INFORMATION_VERSION;
    SuperfetchInfo.Magic = SUPERFETCH_INFORMATION_MAGIC;
    SuperfetchInfo.SuperfetchInformationClass = SuperfetchClass;
    SuperfetchInfo.SuperfetchInformation = Buffer;
    SuperfetchInfo.SuperfetchInformationLength = Size;

    Status = NtQuerySystemInformation(
        SystemSuperfetchInformation,
        &SuperfetchInfo,
        sizeof(SuperfetchInfo),
        RequiredSize);

    return Status;
}

void SuperfetchPrivate()
{
    NTSTATUS Status = 0;
    ULONG Size = sizeof(PF_PRIVSOURCE_QUERY_REQUEST);
    PPF_PRIVSOURCE_QUERY_REQUEST PrivSourceQuery = nullptr;

    do
    {
        VirtualFree(PrivSourceQuery, 0, MEM_RELEASE);
        PrivSourceQuery = (PPF_PRIVSOURCE_QUERY_REQUEST)VirtualAlloc(nullptr, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        PrivSourceQuery->Version = PF_PRIVSOURCE_QUERY_REQUEST_VERSION;
        Status = SuperfetchQuery(SuperfetchPrivSourceQuery, PrivSourceQuery, Size, &Size);
    } while (!NT_SUCCESS(Status));

    for (size_t i = 0; i < PrivSourceQuery->InfoCount; i++)
    {
        auto &Info = PrivSourceQuery->InfoArray[i];
        ProcessInfo[(ULONG_PTR)Info.EProcess & 0x00'00'ff'ff'ff'ff'ff'ff] = &Info;
    }
}

int main(int argc, char *argv[])
{
    NTSTATUS Status;
    BOOLEAN WasEnabled;
    PPF_PHYSICAL_MEMORY_RANGE_INFO_V2 PhysicalMemoryRange;
    ULONG Size;

    if (argc < 3)
    {
        printf("Usage: Superfetch.exe <pid> <va>\n");
        return 1;
    }

    ULONG PID = atoi(argv[1]);
    ULONG_PTR VA = strtoull(argv[2], 0, 16);

    Status = RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &WasEnabled);
    Status |= RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &WasEnabled);
    Size = sizeof(PPF_PHYSICAL_MEMORY_RANGE_INFO_V2);
    PhysicalMemoryRange = nullptr;

    SuperfetchPrivate();

    do
    {
        VirtualFree(PhysicalMemoryRange, 0, MEM_RELEASE);
        PhysicalMemoryRange =
            (PPF_PHYSICAL_MEMORY_RANGE_INFO_V2)VirtualAlloc(nullptr, Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        PhysicalMemoryRange->Version = PF_PHYSICAL_MEMORY_RANGE_INFO_V2_VERSION;
        Status = SuperfetchQuery(SuperfetchMemoryRangesQuery, PhysicalMemoryRange, Size, &Size);
    } while (!NT_SUCCESS(Status));

    for (SIZE_T PageRangeIndex = 0; PageRangeIndex < PhysicalMemoryRange->RangeCount; PageRangeIndex++)
    {
        PF_PHYSICAL_MEMORY_RANGE Range = PhysicalMemoryRange->Ranges[PageRangeIndex];
        ULONG PfnReqSize = sizeof(PF_PFN_PRIO_REQUEST) + Range.PageCount * sizeof(MMPFN_IDENTITY);

        PPF_PFN_PRIO_REQUEST PfnReq =
            (PPF_PFN_PRIO_REQUEST)VirtualAlloc(
                nullptr,
                PfnReqSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE);

        PfnReq->Version = 1;
        PfnReq->RequestFlags = 1;
        PfnReq->PfnCount = Range.PageCount;

        for (SIZE_T PageIndex = 0; PageIndex < Range.PageCount; PageIndex++)
        {
            PfnReq->PageData[PageIndex].PageFrameIndex = Range.BasePfn + PageIndex;
        }

        if (!NT_SUCCESS(SuperfetchQuery(SuperfetchPfnQuery, PfnReq, PfnReqSize, &PfnReqSize)))
        {
            break;
        }

        for (SIZE_T PageIndex = 0; PageIndex < Range.PageCount; PageIndex++)
        {
            auto &Page = PfnReq->PageData[PageIndex];

            if (Page.u2.VirtualAddress == VA && Page.u1.e1.UseDescription == MMPFNUSE_PROCESSPRIVATE)
            {
                auto Physical = Page.PageFrameIndex << 12;
                auto pid = ProcessInfo[Page.u1.e4.UniqueProcessKey]->DbInfo.ProcessId;

                if (pid == PID)
                {
                    printf("%p => %p\n", VA, Physical);
                    break;
                }
            }
        }
    }
}