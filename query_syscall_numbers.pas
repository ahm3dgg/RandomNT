type
  TStub = record
    Name: string;
    Address: Pointer;
    SSN: integer;
  end;
  
  TStubMap = specialize TDictionary<string, TStub>; 
  
var 
  StubsMap: TStubMap;

  // just flexing my assembly skills.
  function GetNTDLLBase(): Pointer; assembler; nostackframe;
  label
    search_base, found;
  asm
           MOV     RAX, GS:[$60]
           MOV     RAX, [RAX+$18]
           ADD     RAX, $0000000000000fff
           AND     RAX, $fffffffffffff000
           search_base:
           CMP     word ptr [RAX], $5A4D
           JE      found
           SUB     RAX, $1000
           JMP     search_base
           found:
           RET
  end;
  
function PE_GetNTHeaders(ModuleBase: Pointer): PIMAGE_NT_HEADERS;
begin
   Result := ModuleBase + PIMAGE_DOS_HEADER(ModuleBase)^.e_lfanew;
 end; 
  
procedure PE_InitNTStubMap();
var
   NTDLLBase: Pointer;

    Stubs: array of TStub;
    ExportDirectory: PIMAGE_EXPORT_DIRECTORY;
    ExportName: string;
    NameRVAs: PUInt32;
    NameOrdinals: PUInt16;
    NameOrdinal: uint16;
    NumberOfNames: integer;
    FunctionNamesRVAs: PUInt32;
    StubsLength: integer = 0;

    I: integer;
    J: integer;
    Tmp: TStub;
  begin
    NTDLLBase := GetNTDLLBase();

    ExportDirectory := NTDLLBase + PE_GetNTHeaders(NTDLLBase)^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    NameRVAs := NTDLLBase + ExportDirectory^.AddressOfNames;
    NumberOfNames := ExportDirectory^.NumberOfNames;
    FunctionNamesRVAs := NTDLLBase + ExportDirectory^.AddressOfFunctions;
    NameOrdinals := NTDLLBase + ExportDirectory^.AddressOfNameOrdinals;

    Stubs := [];
    StubsMap := TStubMap.Create;

    SetLength(Stubs, NumberOfNames);

    for I := 0 to NumberOfNames - 1 do
    begin
      ExportName := string(PChar(NTDLLBase + NameRVAs[I]));
      if not (ExportName.Contains('_')) and (ExportName.StartsWith('Nt')) then
      begin
        NameOrdinal := NameOrdinals[I];

        Stubs[StubsLength].Name := ExportName;
        Stubs[StubsLength].Address := NTDLLBase + FunctionNamesRVAs[NameOrdinal];

        StubsLength += 1;
      end;
    end;

    SetLength(Stubs, StubsLength);

    // The worst sorting algorithm of them all.
    for I := 0 to StubsLength - 1 do
    begin
      for J := I + 1 to StubsLength - 1 do
      begin
        if Stubs[I].Address > Stubs[J].Address then
        begin
          Tmp := Stubs[I];
          Stubs[I] := Stubs[J];
          Stubs[J] := Tmp;
        end;
      end;
    end;

    for I := 0 to StubsLength - 1 do
    begin
      Stubs[I].SSN := I;
      StubsMap.Add(Stubs[I].Name, Stubs[I]);
    end;
  end;