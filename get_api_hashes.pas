{$AsmMode intel}

program PascalRizz;

uses Windows, SysUtils;

function Checksum(apiname: PChar): UInt32; assembler;
asm
                 mov esi, apiname

// Replace this by your algorithm starting from here.
                 xor     edi, edi
                 cld

@loc_401171:
                 xor     eax, eax
                 lodsb
                 cmp     al, ah
                 jz      @loc_40117F
                 ror     edi, 0Dh
                 add     edi, eax
                 jmp     @loc_401171
@loc_40117F:
// After fininshing don't forget to place the final hash inside eax.
                 mov eax, edi
end;

var
  hKernel32: Handle;
  NTHeaders: PIMAGE_NT_HEADERS;
  ExportDir: PIMAGE_EXPORT_DIRECTORY;
  NameRVAs: PUInt32;
  ExportName: PChar;
  ExportHash: UInt32;
  I: Integer;
  Enum: string;
  Module: string;
  OutFile: TextFile;
begin

  if ParamCount <> 1 then
  begin
    WriteLn('Usage: pascalrizz.exe <module_name>');
    Exit;
  end;

  Module := ParamStr(1);
  hKernel32 := GetModuleHandleA(PChar(Module));
  NTHeaders := PIMAGE_NT_HEADERS(hKernel32 + PIMAGE_DOS_HEADER(hKernel32)^.e_lfanew);
  ExportDir := PIMAGE_EXPORT_DIRECTORY(hKernel32 + NTHeaders^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

  NameRVAs := PUInt32(hKernel32 + ExportDir^.AddressOfNames);

  Enum := Format('enum %s_api_hashes {', [Module]) + LineEnding;
  for I := 0 to ExportDir^.NumberOfNames - 1 do
  begin
    ExportName := PChar(hKernel32 + NameRVAs[I]);
    ExportHash := Checksum(ExportName);
    Enum += Format('    %s_%s = 0x%X,' + LineEnding, [Module, ExportName, ExportHash]);
  end;

  Enum += '};' + LineEnding;


  AssignFile(OutFile,  Format('%s_hashes.h', [Module]));
  Rewrite(OutFile);
  WriteLn(OutFile, Enum);
  CloseFile(OutFile);
end.