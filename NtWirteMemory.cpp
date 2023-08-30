// NtWirteMemory.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>

using namespace std;


HANDLE ZwOpenProcess(DWORD pid, DWORD status) {
	typedef struct POBJECT_ATTRIBUTES {
		DWORD           Length;
		DWORD          RootDirectory;
		DWORD			ObjectName;
		DWORD           Attributes;
		DWORD           SecurityDescriptor;
		DWORD           SecurityQualityOfService;
	} OBJECT_ATTRIBUTES;
	typedef struct PCLIENT_ID
	{
		DWORD x, y;
	};
	typedef
		NTSTATUS
		(NTAPI* Ptr_NtOpenProcess)(
			PHANDLE ProcessHandle,
			ACCESS_MASK DesiredAccess,
			POBJECT_ATTRIBUTES* ObjectAttributes,
			PCLIENT_ID* ClientId
			);
	LPCSTR moudlename = TEXT("ntdll.dll");
	LPCSTR callname = TEXT("NtOpenProcess");
	Ptr_NtOpenProcess NtOpenProcess = (Ptr_NtOpenProcess)GetProcAddress(GetModuleHandle(moudlename), callname);
	POBJECT_ATTRIBUTES m_temp1 = { 24 };
	HANDLE m_temp3 = 0;
	PCLIENT_ID m_temp2 = { pid};
	status = NtOpenProcess(&m_temp3, 2035711, &m_temp1, &m_temp2);
	if (m_temp3 != 0)
		return m_temp3;
	status = GetLastError();
	return 0;
}
template <typename Address,typename Num>
DWORD ZwWirteProceeMemory(DWORD pid, Address address, Num num) {
	typedef
		NTSTATUS
		(NTAPI* Ptr_NtWriteVirtualMemory)(
			HANDLE ProcessHandle,
			PVOID BaseAddress,
			PVOID Buffer,
			ULONG BufferLength,
			PULONG ReturnLength OPTIONAL
			);

	LPCSTR moudlename = TEXT("ntdll.dll");
	LPCSTR callname = TEXT("NtWriteVirtualMemory");
	Ptr_NtWriteVirtualMemory NtWriteVirtualMemory = (Ptr_NtWriteVirtualMemory)GetProcAddress(GetModuleHandle(moudlename), callname);
	
	DWORD status = 0;
	HANDLE hAndle = ZwOpenProcess(pid, status);
	DWORD OldProtect;
	
	if (hAndle != 0)
	{
		VirtualProtectEx(hAndle, (LPVOID)address, sizeof(num), PAGE_READWRITE, &OldProtect);
		status = NtWriteVirtualMemory(hAndle, (LPVOID)address, &num, sizeof(num), nullptr);
		VirtualProtectEx(hAndle, (LPVOID)address, sizeof(num), OldProtect, nullptr);
		if (status)
			return 1;
		return GetLastError();
	}
	return GetLastError();
}
template <typename Address,typename Ret>
Ret ZwReadProcessMemory(DWORD pid, Address address,DWORD status){/*status 用于排查错误*/
	typedef
		NTSTATUS(NTAPI* Ptr_NtReadVirtualMemory)
		(IN HANDLE               ProcessHandle,
			IN PVOID                BaseAddress,
			OUT PVOID               Buffer,
			IN ULONG                NumberOfBytesToRead,
			OUT PULONG              NumberOfBytesReaded OPTIONAL);
	LPCSTR moudlename = TEXT("ntdll.dll");
	LPCSTR callname = TEXT("NtReadVirtualMemory");
	Ptr_NtReadVirtualMemory NtReadVirtualMemory = (Ptr_NtReadVirtualMemory)GetProcAddress(GetModuleHandle(moudlename), callname);
	Ret Buffer;
	HANDLE hAndle = ZwOpenProcess(pid, status);
	if (hAndle != 0)
	{
		NtReadVirtualMemory(hAndle, (LPVOID)address, &Buffer, sizeof(Buffer), nullptr);
		if (Buffer != 0)
			return Buffer;
		status = GetLastError();
		return 0;
	}
	status = GetLastError();
	return 0;
}

void Errorinfo(){

    cout << GetLastError() << endl;
}

bool UpPrivilegeValue()
{
	//OpenProcessToken()函数用来打开与进程相关联的访问令牌
	HANDLE hToken = nullptr;
	if (FALSE == OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken))
	{
		return false;
	}
	//LookupPrivilegeValue()函数查看系统权限的特权值
	LUID luid;
	if (FALSE == LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
	{
		CloseHandle(hToken);
		return false;
	}
	//调整权限设置
	TOKEN_PRIVILEGES Tok;
	Tok.PrivilegeCount = 1;
	Tok.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	Tok.Privileges[0].Luid = luid;
	if (FALSE == AdjustTokenPrivileges(hToken, FALSE, &Tok, sizeof(Tok), nullptr, nullptr))
	{
		CloseHandle(hToken);
		return false;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);
	return true;
}

int main()
{
	UpPrivilegeValue();
    HANDLE hAndle = nullptr;
    HANDLE hAndle1 = nullptr;
    DWORD pid = NULL;
    HWND hwnd = nullptr;
	DWORD m_status = 0;
    hwnd = FindWindowA("MainWindow","植物大战僵尸中文版");
    GetWindowThreadProcessId(hwnd, &pid);
    hAndle = OpenProcess(PROCESS_ALL_ACCESS,0,pid);
	DWORD B = GetLastError();



	hAndle1 = ZwOpenProcess(pid, m_status);
	DWORD status = 0;
	ZwWirteProceeMemory<DWORD, DWORD>(1, 0x15E47F00, 999);





    std::cout << "阳光的数值为->" << ZwReadProcessMemory<DWORD, DWORD>(1, 0x15E47F00, status) << "错误代码："<< status;
}
