
#define _WIN32_WINNT 0x0601
#define PSAPI_VERSION 1
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

// ==================== 工具函数 ====================

// 检测是否以管理员身份运行
BOOL IsAdmin() {
	BOOL b;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;
	b = AllocateAndInitializeSid(
		&NtAuthority, 2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&AdministratorsGroup);
	if (b) {
		CheckTokenMembership(NULL, AdministratorsGroup, &b);
		FreeSid(AdministratorsGroup);
	}
	return b;
}

// 提升指定权限（失败不报错，返回FALSE表示无权限）
BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;
	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
		CloseHandle(hToken);
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;
	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	BOOL ret = (GetLastError() == ERROR_SUCCESS);
	CloseHandle(hToken);
	return ret;
}

// 获取空闲物理内存(MB)
SIZE_T GetAvailableMemoryMB() {
	MEMORYSTATUSEX memStatus;
	memStatus.dwLength = sizeof(memStatus);
	GlobalMemoryStatusEx(&memStatus);
	return static_cast<SIZE_T>(memStatus.ullAvailPhys / (1024 * 1024));
}

// 获取总物理内存(MB)
SIZE_T GetTotalMemoryMB() {
	MEMORYSTATUSEX memStatus;
	memStatus.dwLength = sizeof(memStatus);
	GlobalMemoryStatusEx(&memStatus);
	return static_cast<SIZE_T>(memStatus.ullTotalPhys / (1024 * 1024));
}

// ==================== 7项优化技术实现 ====================

// 1. 清理所有进程工作集（需要管理员权限才能清理其他进程）
int Optimize_WorkingSet(BOOL quiet) {
	// 非管理员：只清理自身进程
	if (!IsAdmin()) {
		EmptyWorkingSet(GetCurrentProcess());
		if (!quiet) std::cout << "  [工作集] 仅清理自身进程 (非管理员模式)" << std::endl;
		return 1;
	}

	int success = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return -1;

	PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
	if (!Process32First(hSnapshot, &pe32)) { CloseHandle(hSnapshot); return -1; }

	do {
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA,
			FALSE, pe32.th32ProcessID);
		if (hProcess) {
			if (EmptyWorkingSet(hProcess)) success++;
			CloseHandle(hProcess);
		}
	} while (Process32Next(hSnapshot, &pe32));

	CloseHandle(hSnapshot);
	if (!quiet) std::cout << "  [工作集] 清理 " << success << " 个进程" << std::endl;
	return success;
}

// 2. 清理系统文件缓存（需要管理员权限）
BOOL Optimize_SystemCache(BOOL quiet) {
	if (!IsAdmin()) {
		if (!quiet) std::cout << "  [缓存] 跳过 (需要管理员)" << std::endl;
		return FALSE;
	}

	typedef BOOL(WINAPI *pSetSystemFileCacheSize)(SIZE_T, SIZE_T, DWORD);
	HMODULE hKernel = GetModuleHandle(L"kernel32.dll");
	if (!hKernel) return FALSE;
	pSetSystemFileCacheSize SetSystemFileCacheSize =
		(pSetSystemFileCacheSize)GetProcAddress(hKernel, "SetSystemFileCacheSize");
	if (!SetSystemFileCacheSize) return FALSE;

	BOOL ret = SetSystemFileCacheSize(-1, -1, 0);
	if (!quiet) {
		if (ret) std::cout << "  [缓存] 系统文件缓存已刷新" << std::endl;
	}
	return ret;
}

// 3. 清空备用内存列表（需要管理员权限）
BOOL Optimize_StandbyList(BOOL quiet) {
	if (!IsAdmin()) {
		if (!quiet) std::cout << "  [备用列表] 跳过 (需要管理员)" << std::endl;
		return FALSE;
	}

	typedef enum _MEMORY_LIST_TYPE {
		MemoryPurgeStandbyList = 4,
		MemoryPurgeLowPriorityStandbyList = 5
	} MEMORY_LIST_TYPE;
	typedef LONG NTSTATUS;
	typedef NTSTATUS(WINAPI *PNtSetSystemInformation)(DWORD, PVOID, ULONG);

	HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
	if (!hNtDll) return FALSE;
	PNtSetSystemInformation NtSetSystemInformation =
		(PNtSetSystemInformation)GetProcAddress(hNtDll, "NtSetSystemInformation");
	if (!NtSetSystemInformation) return FALSE;

	MEMORY_LIST_TYPE cmds[] = { MemoryPurgeStandbyList, MemoryPurgeLowPriorityStandbyList };
	BOOL anySuccess = FALSE;
	for (int i = 0; i < 2; i++) {
		NTSTATUS status = NtSetSystemInformation(80, &cmds[i], sizeof(cmds[i]));
		if (status == 0) anySuccess = TRUE;
	}
	if (!quiet) {
		if (anySuccess) std::cout << "  [备用列表] 已清空" << std::endl;
	}
	return anySuccess;
}

// 4. 内存压缩（需要管理员权限）
BOOL Optimize_MemoryCompaction(BOOL quiet) {
	if (!IsAdmin()) {
		if (!quiet) std::cout << "  [压缩] 跳过 (需要管理员)" << std::endl;
		return FALSE;
	}

	typedef LONG NTSTATUS;
	typedef NTSTATUS(WINAPI *PNtSetSystemInformation)(DWORD, PVOID, ULONG);
	HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
	if (!hNtDll) return FALSE;
	PNtSetSystemInformation NtSetSystemInformation =
		(PNtSetSystemInformation)GetProcAddress(hNtDll, "NtSetSystemInformation");
	if (!NtSetSystemInformation) return FALSE;

	DWORD cmd = 6;
	NTSTATUS status = NtSetSystemInformation(80, &cmd, sizeof(cmd));
	if (!quiet) {
		if (status == 0) std::cout << "  [压缩] 内存压缩完成" << std::endl;
	}
	return (status == 0);
}

// 5. 智能内存冲刷（不需要特殊权限）
BOOL Optimize_MemoryFlush(BOOL quiet) {
	SIZE_T totalMB = GetTotalMemoryMB();
	SIZE_T availMB = GetAvailableMemoryMB();
	SIZE_T flushSize = 0;
	SIZE_T targetByFree = availMB * 30 / 100;
	SIZE_T targetByTotal = totalMB * 20 / 100;
	flushSize = min(targetByFree, targetByTotal);
	if (flushSize < 64) flushSize = 64;
	if (flushSize > 1024) flushSize = 1024;
	flushSize *= 1024 * 1024;

	LPVOID pMem = VirtualAlloc(NULL, flushSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pMem) {
		flushSize = 128 * 1024 * 1024;
		pMem = VirtualAlloc(NULL, flushSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	}
	if (pMem) {
		SecureZeroMemory(pMem, flushSize);
		VirtualFree(pMem, 0, MEM_RELEASE);
		if (!quiet) std::cout << "  [冲刷] " << (flushSize / (1024 * 1024)) << " MB" << std::endl;
		return TRUE;
	}
	return FALSE;
}

// 6. 扩展工作集整理（不需要特殊权限）
BOOL Optimize_WorkingSetEx(BOOL quiet) {
	typedef BOOL(WINAPI *pSetProcessWorkingSetSizeEx)(HANDLE, SIZE_T, SIZE_T, DWORD);
	HMODULE hKernel = GetModuleHandle(L"kernel32.dll");
	if (!hKernel) return FALSE;
	pSetProcessWorkingSetSizeEx SetProcessWorkingSetSizeEx =
		(pSetProcessWorkingSetSizeEx)GetProcAddress(hKernel, "SetProcessWorkingSetSizeEx");
	if (!SetProcessWorkingSetSizeEx) {
		return FALSE;
	}

	BOOL ret = SetProcessWorkingSetSizeEx(GetCurrentProcess(), -1, -1,
		QUOTA_LIMITS_HARDWS_MIN_ENABLE | QUOTA_LIMITS_HARDWS_MAX_ENABLE);
	if (!quiet && ret) std::cout << "  [扩展工作集] 已整理" << std::endl;
	return ret;
}

// 7. 进程堆压缩（不需要特殊权限）
BOOL Optimize_HeapCompact(BOOL quiet) {
	HANDLE hHeap = GetProcessHeap();
	SIZE_T compressed = HeapCompact(hHeap, 0);
	if (!quiet && compressed > 0) {
		std::cout << "  [堆压缩] 释放 " << compressed << " 字节" << std::endl;
	}
	return TRUE;
}

// ==================== 主程序入口 ====================
int main(int argc, char* argv[]) {
	BOOL quietMode = FALSE;
	if (argc > 1 && strcmp(argv[1], "-q") == 0) {
		quietMode = TRUE;
	}

	BOOL isAdmin = IsAdmin();
	SIZE_T totalMem = GetTotalMemoryMB();
	SIZE_T freeBefore = GetAvailableMemoryMB();
	BOOL memoryPressure = (freeBefore * 100 / totalMem) < 70;

	if (isAdmin) {
		SetPrivilege(TEXT("SeDebugPrivilege"), TRUE);
		SetPrivilege(TEXT("SeIncreaseQuotaPrivilege"), TRUE);
		SetPrivilege(TEXT("SeProfileSingleProcessPrivilege"), TRUE);
	}

	DWORD startTick = GetTickCount();

	// 全部静默执行
	Optimize_WorkingSet(TRUE);
	Optimize_SystemCache(TRUE);
	Optimize_StandbyList(TRUE);
	Optimize_MemoryCompaction(TRUE);
	if (memoryPressure) Optimize_MemoryFlush(TRUE);
	Optimize_WorkingSetEx(TRUE);
	Optimize_HeapCompact(TRUE);

	DWORD endTick = GetTickCount();
	double elapsedSec = (endTick - startTick) / 1000.0;

	SIZE_T freeAfter = GetAvailableMemoryMB();
	SIZE_T freed = (freeAfter > freeBefore) ? (freeAfter - freeBefore) : 0;

	if (!quietMode) {
		double totalGiB = totalMem / 1024.0;
		std::cout << "Total: " << totalGiB << " GiB, "
			<< "Free: " << freeBefore << " -> " << freeAfter << " MiB, "
			<< "Freed: " << freed << " MiB, "
			<< "Time: " << elapsedSec << " s" << std::endl;
	}
	else {
		std::cout << freeBefore << " -> " << freeAfter << " MB" << std::endl;
	}

	return 0;
}
