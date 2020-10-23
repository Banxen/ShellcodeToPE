#include<Windows.h>
#include<stdio.h>

#define SHELLCODE 23
#define FILE_ALIGNMENT 512
#define SECTION_ALIGNMENT 4096
#define SIZE_OF_HEADERS 512
#define OFFSET_SIZEOFCODE 0xCC
#define OFFSET_SIZEOFIMAGE 0x100
#define OFFSET_SECTION_VIRTUAL_SIZE 0x1B0
#define OFFSET_SECTION_RVA 0x1B4
#define OFFSET_SECTION_RAW_SIZE 0x1B8

int main(int argc, char **argv) {
	HRSRC resourceInitHandle;
	HGLOBAL resourceHandle;
	DWORD resourceSize = 0;
	LPVOID resourcePointer;
	BYTE* resourceCharPointer;
	HANDLE hFile;
	HANDLE hShellcode;
	DWORD shellcodeSize = 0;
	LPVOID allocatedBuffer;
	DWORD sectionSizeFA = 0;
	DWORD sectionSizeSA = 0;
	DWORD sizeOfImage = 0;
	HANDLE hOutput;
	UCHAR usage[] = "[USAGE]: ShellcodeToPE <shellcode_file_path>";
	UCHAR PEName[] = "OutputPE.bin";
	DWORD bytesReadWrite = 0;

	if (argc == 2) {
		resourceInitHandle = FindResource(NULL, MAKEINTRESOURCE(SHELLCODE), RT_RCDATA);
		resourceHandle = LoadResource(NULL, resourceInitHandle);
		resourceSize = SizeofResource(GetModuleHandle(NULL) ,resourceInitHandle);
		resourcePointer = LockResource(resourceHandle);
		resourceCharPointer = (BYTE*)resourcePointer;
		
		printf("Opening Shellcode File: [%s]\n", argv[1]);
		hShellcode = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		shellcodeSize = GetFileSize(hShellcode, NULL);
		printf("Shellcode Size: [0x%04x]\n", shellcodeSize);

		sectionSizeFA = shellcodeSize + (FILE_ALIGNMENT - shellcodeSize % FILE_ALIGNMENT);
		printf("Shellcode Size [File Alignment] : [0x%04x]\n", sectionSizeFA);
		sectionSizeSA = shellcodeSize + (SECTION_ALIGNMENT - shellcodeSize % SECTION_ALIGNMENT);
		printf("Shellcode Size [Section Alignment] : [0x%04x]\n", sectionSizeSA);
		sizeOfImage = *((DWORD*)(resourceCharPointer+ OFFSET_SECTION_RVA)) + sectionSizeSA;
		printf("SizeOfImage : [0x%04x]\n", sizeOfImage);

		printf("Allocating buffer to read\n");
		allocatedBuffer = VirtualAlloc(NULL, sectionSizeFA, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		
		printf("Reading Shellcode: [%s]\n", argv[1]);
		ReadFile(hShellcode, allocatedBuffer, shellcodeSize, &bytesReadWrite, NULL);

		printf("Generating PE File: [%s]\n", PEName);
		hFile = CreateFileA(PEName, GENERIC_READ|GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		
		printf("Modifying required fields\n");
		WriteFile(hFile, resourceCharPointer, resourceSize, &bytesReadWrite, NULL);
		SetFilePointer(hFile, OFFSET_SIZEOFCODE, NULL, FILE_BEGIN);
		WriteFile(hFile, &sectionSizeFA, sizeof(sectionSizeFA), &bytesReadWrite, NULL);
		SetFilePointer(hFile, OFFSET_SIZEOFIMAGE, NULL, FILE_BEGIN);
		WriteFile(hFile, &sizeOfImage, sizeof(sizeOfImage), &bytesReadWrite, NULL);
		SetFilePointer(hFile, OFFSET_SECTION_VIRTUAL_SIZE, NULL, FILE_BEGIN);
		WriteFile(hFile, &sectionSizeSA, sizeof(sectionSizeSA), &bytesReadWrite, NULL);
		SetFilePointer(hFile, OFFSET_SECTION_RAW_SIZE, NULL, FILE_BEGIN);
		WriteFile(hFile, &sectionSizeFA, sizeof(sectionSizeFA), &bytesReadWrite, NULL);
		SetFilePointer(hFile, 0, NULL, FILE_END);

		printf("Writing Shellcode to Generated PE\n");
		WriteFile(hFile, allocatedBuffer, sectionSizeFA, &bytesReadWrite, NULL);
		
		printf("Cleaning the mess\n");
		CloseHandle(hShellcode);
		VirtualFree(allocatedBuffer, shellcodeSize, MEM_DECOMMIT);
		CloseHandle(hFile);
		printf("PE File Generated :)\n");
	}
	else {
		hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
		WriteConsoleA(hOutput, usage, sizeof(usage), &bytesReadWrite, NULL);
		CloseHandle(hOutput);
	}
	
	getchar();
	return 0;
}