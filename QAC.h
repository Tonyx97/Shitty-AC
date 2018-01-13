#pragma once

#ifndef QUANTUM_AC_H
#define QUANTUM_AC_H

#include <Windows.h>

#include "../CESTL/CEV.h"
#include "../CESTL/CEM.h"
#include "../ThreadsSystem/ThreadSystem.h"

enum eFunctionsHooks
{
	MAKE_CURRENT,
	SWAP_BUFFERS,
	DRAW_ARRAYS,
	BIND_VERTEX_ARRAY
};

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

class CQuantumAC
{
private:

	struct CFunctionsData
	{
		uint m_dwAddress;
		cev<char> m_vData;
		bool m_bEnabled;
	};

	cem<eFunctionsHooks, CFunctionsData> m_mapFunctionsHooks;
	CEThreadHandle m_pHeartbeatThread;
	uint m_dwGamePID;

public:

	CQuantumAC();
	~CQuantumAC();

	void Initialize();
	void Wait();
	void SaveFunction(CFunctionsData& pFunctionData, uint& dwFunction);
	void CheckHooks();
	void CheckProcesses();
	void SetHookDetectionEnabled(const eFunctionsHooks& eFunction, const bool& bEnabled);
	void GetProcessFullPath(const HANDLE& pHandle, char* szBuf, const uint& uiSize);


	bool GetProcessBaseAddress(const uint& dwPID, uint64& dwBaseAddress, uint& dwSize);
	bool CheckFunction(const eFunctionsHooks& eFunction);
	bool CheckSig(const HANDLE& pProcess, char* pProcessMemory, const uint& dwBase, const uint& dwSize, uint& dwFoundAddress, const std::initializer_list<char>& vPattern);


};

extern ceup<CQuantumAC> g_QAC;

#endif