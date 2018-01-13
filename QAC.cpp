#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <Winternl.h>
#include <ntstatus.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include <gl/glew.h>

#include "QAC.h"

#include "../glm.h"
#include "../ThreadsSystem/ThreadSystem.h"
#include "../Timers/Timers.h"
#include "../CrashHandler/CrashHandler.h"
#include "../CESTL/CEM.h"
#include "../CESTL/CEV.h"
#include "../Renderer/Renderer.h"
#include "../Console/Console.h"
#include "../InternalGlobalVars/IGVars.h"

ceup<CQuantumAC> g_QAC;


void QuantumACThread()
{
	__try
	{
		while (!g_Renderer->IsClosing())
		{
			/*g_QAC->CheckHooks();
			g_QAC->CheckProcesses();

			g_TimeManager->Sleep<ms>(2500);*/
			g_TimeManager->Sleep<ms>(100);
		}
	}
	__except (g_CrashHandler->HandleCrash(GetExceptionInformation()))
	{
		exit(1);
	}
}

CQuantumAC::CQuantumAC()
{

}

CQuantumAC::~CQuantumAC()
{
	
}

void CQuantumAC::Initialize()
{
	DWORD dwMakeCurrent = reinterpret_cast<DWORD>(wglMakeCurrent);
	DWORD dwSwapBuffers = reinterpret_cast<DWORD>(SwapBuffers);
	DWORD dwDrawArrays = reinterpret_cast<DWORD>(glDrawArrays);
	DWORD dwBindVertexArray = reinterpret_cast<DWORD>(glBindVertexArray);

	g_Console->Print(DColor::Green, __FILE__, __FUNCTION__, "-------FUNCTIONS HOOKED-------");
	g_Console->Print(DColor::Green, __FILE__, __FUNCTION__, "wglMakeCurrent: %X (%X)", dwMakeCurrent, dwMakeCurrent - (DWORD)GetModuleHandle("opengl32.dll"));
	g_Console->Print(DColor::Green, __FILE__, __FUNCTION__, "SwapBuffers: %X (%X)", dwSwapBuffers, dwSwapBuffers - (DWORD)GetModuleHandle("gdi32.dll"));
	g_Console->Print(DColor::Green, __FILE__, __FUNCTION__, "glDrawArrays: %X (%X)", dwDrawArrays, dwDrawArrays - (DWORD)GetModuleHandle("opengl32.dll"));
	g_Console->Print(DColor::Green, __FILE__, __FUNCTION__, "glBindVertexArray: %X (%X)", dwBindVertexArray, dwBindVertexArray - (DWORD)GetModuleHandle("glew32.dll"));

	g_Console->Print(DColor::Green, __FILE__, __FUNCTION__, "------------------------------");

	SaveFunction(m_mapFunctionsHooks[MAKE_CURRENT], dwMakeCurrent);
	SaveFunction(m_mapFunctionsHooks[SWAP_BUFFERS], dwSwapBuffers);
	SaveFunction(m_mapFunctionsHooks[DRAW_ARRAYS], dwDrawArrays);
	SaveFunction(m_mapFunctionsHooks[BIND_VERTEX_ARRAY], dwBindVertexArray);

	m_pHeartbeatThread = g_ThreadSystem->CECreateThread(QuantumACThread);

	m_dwGamePID = GetCurrentProcessId();

	g_Console->Print(DColor::Green, __FILE__, __FUNCTION__, "Quantum Anti-Cheat loaded (Thread %X)", m_pHeartbeatThread);
}

void CQuantumAC::Wait()
{
	g_ThreadSystem->CEWaitThread(m_pHeartbeatThread);
}

void CQuantumAC::SaveFunction(CFunctionsData& pFunctionData, uint& dwFunction)
{
	BYTE bByte = 0;

	pFunctionData.m_dwAddress = dwFunction;

	while (bByte != 0xCC)
	{
		bByte = *(BYTE*)(dwFunction++);
		pFunctionData.m_vData.Add(bByte);
	}

	pFunctionData.m_bEnabled = true;
	pFunctionData.m_vData.Pop();
}

void CQuantumAC::CheckHooks()
{
	if (m_mapFunctionsHooks[MAKE_CURRENT].m_bEnabled)
		CheckFunction(MAKE_CURRENT);
	if (m_mapFunctionsHooks[SWAP_BUFFERS].m_bEnabled)
		CheckFunction(SWAP_BUFFERS);
	if (m_mapFunctionsHooks[DRAW_ARRAYS].m_bEnabled)
		CheckFunction(DRAW_ARRAYS);
	if (m_mapFunctionsHooks[BIND_VERTEX_ARRAY].m_bEnabled)
		CheckFunction(BIND_VERTEX_ARRAY);
}

void CQuantumAC::CheckProcesses()
{
	HANDLE hPID = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 pEntry;

	if (Process32First(hPID, &pEntry))
	{
		do
		{
			if (pEntry.th32ProcessID == m_dwGamePID)
				continue;

			PROCESS_BASIC_INFORMATION pPBI;
			HANDLE pProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pEntry.th32ProcessID);

			if (!pProcess)
				continue;

			if (!NtQueryInformationProcessQAC(pProcess, PROCESSINFOCLASS::ProcessBasicInformation, &pPBI, sizeof(pPBI)))
			{
				CloseHandle(pProcess);
				continue;
			}
			
			char szFullPath[512];
			GetProcessFullPath(pProcess, szFullPath, sizeof(szFullPath));

			uint64 dwBaseAdd;
			uint dwSize;

			GetProcessBaseAddress(pEntry.th32ProcessID, dwBaseAdd, dwSize);
			
			char* pProcessVirtualMemory = (char*)VirtualAlloc(0, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

			if (!pProcessVirtualMemory || !ReadProcessMemory(pProcess, reinterpret_cast<void*>(dwBaseAdd), pProcessVirtualMemory, dwSize, NULL))
			{
				CloseHandle(pProcess);
				continue;
			}

			g_Console->Print_2(DColor::Green, "----------- Scanning '%s' -----------", pEntry.szExeFile);

			uint dwFound;

			//if (CheckSig(pProcess, pProcessVirtualMemory, dwBaseAdd, dwSize, dwFound, { (char)0x55, (char)0x8B, (char)0xEC, 0x6A, 0x00, 0x53, 0x56, 0x33, 0xC0, 0x55, 0x68, 0x25, 0x4C, 0x40, 0x00, 0x64, 0xFF, 0x30 }))
			//	g_Console->Print(DColor::Red, __FILE__, __FUNCTION__, "Suspicious Program Part Detected at 0x%X of '%s'!", dwFound, pEntry.szExeFile);

			g_Console->Print_2(DColor::Green, "Path: '%s'", szFullPath);
			g_Console->Print_2(DColor::Green, "Base: 0x%X", dwBaseAdd);
			g_Console->Print_2(DColor::Green, "Size: 0x%X", dwSize);
			g_Console->Print_2(DColor::Green, "Buffer: 0x%X", pProcessVirtualMemory);

			if (!VirtualFree(pProcessVirtualMemory, 0, MEM_RELEASE))
				g_Console->Print(DColor::Red, __FILE__, __FUNCTION__, "Critical memory leak found!");

			CloseHandle(pProcess);
			
		} while (Process32Next(hPID, &pEntry));
	}
	CloseHandle(hPID);
}

void CQuantumAC::SetHookDetectionEnabled(const eFunctionsHooks& eFunction, const bool& bEnabled)
{
	m_mapFunctionsHooks[eFunction].m_bEnabled = bEnabled;
}

void CQuantumAC::GetProcessFullPath(const HANDLE& pHandle, char* szBuf, const uint& uiSize)
{
	GetModuleFileNameEx(pHandle, NULL, szBuf, uiSize);
}

bool CQuantumAC::GetProcessBaseAddress(const uint& dwPID, uint64& dwBaseAddress, uint& dwSize)
{
	HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (!hModule)
		return false;

	MODULEENTRY32 mEntry;

	mEntry.dwSize = sizeof(MODULEENTRY32);

	Module32First(hModule, &mEntry);

	dwBaseAddress = reinterpret_cast<uint64>(mEntry.modBaseAddr);
	dwSize = mEntry.modBaseSize;

	CloseHandle(hModule);

	return true;
}

bool CQuantumAC::CheckFunction(const eFunctionsHooks& eFunction)
{
	uint dwFunction = m_mapFunctionsHooks[eFunction].m_dwAddress;

	if (!dwFunction)
		return false;

	char bByte = 0;
	uint i = 0;

	while (bByte != 0xCC)
	{
		bByte = *(char*)(dwFunction++);

		if (bByte != m_mapFunctionsHooks[eFunction].m_vData[i])
		{
			g_Console->Print(DColor::Red, __FILE__, __FUNCTION__, "Hook Detected at %X !", m_mapFunctionsHooks[eFunction].m_dwAddress);
			return true;
		}

		++i;
	}
}

bool CQuantumAC::CheckSig(const HANDLE& pProcess, char* pProcessMemory, const uint& dwBase, const uint& dwSize, uint& dwFoundAddress, const std::initializer_list<char>& vPattern)
{
	std::vector<char> vPatternArray(vPattern.begin(), vPattern.end());

	DWORD dwStart = dwBase, iMatches = 0;

	while (dwStart < dwSize)
	{
		if (iMatches >= vPattern.size())
			return (dwFoundAddress = dwStart - vPattern.size()) != 0;

		if (pProcessMemory[dwStart % dwBase] == vPatternArray[iMatches])
			++iMatches;
		else
			iMatches = 0;

		++dwStart;
	}

	return false;
}