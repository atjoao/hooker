#include <windows.h>

static HMODULE g_realDll = nullptr;

static FARPROC GetRealProc(const char *name) {
  if (!g_realDll) {
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);

    char ourName[MAX_PATH];
    HMODULE us = nullptr;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                       (LPCSTR)GetRealProc, &us);
    GetModuleFileNameA(us, ourName, MAX_PATH);

    char *fname = strrchr(ourName, '\\');
    fname = fname ? fname + 1 : ourName;

    if (_strnicmp(fname, "version", 7) == 0) {
      strcat_s(path, "\\version.dll");
    } else if (_strnicmp(fname, "dinput8", 7) == 0) {
      strcat_s(path, "\\dinput8.dll");
    } else {
      strcat_s(path, "\\winmm.dll");
    }

    g_realDll = LoadLibraryA(path);
  }
  return g_realDll ? GetProcAddress(g_realDll, name) : nullptr;
}

void FreeRealDll() {
  if (g_realDll) {
    FreeLibrary(g_realDll);
    g_realDll = nullptr;
  }
}

#define FORWARD(name)                                                          \
  static FARPROC _fp_##name = nullptr;                                         \
  extern "C" LONG_PTR __cdecl _fwd_##name(LONG_PTR a, LONG_PTR b, LONG_PTR c,  \
                                          LONG_PTR d, LONG_PTR e, LONG_PTR f,  \
                                          LONG_PTR g, LONG_PTR h) {            \
    if (!_fp_##name)                                                           \
      _fp_##name = GetRealProc(#name);                                         \
    if (!_fp_##name)                                                           \
      return 0;                                                                \
    typedef LONG_PTR(__cdecl * fn_t)(LONG_PTR, LONG_PTR, LONG_PTR, LONG_PTR,   \
                                     LONG_PTR, LONG_PTR, LONG_PTR, LONG_PTR);  \
    return ((fn_t)_fp_##name)(a, b, c, d, e, f, g, h);                         \
  }

// version.dll exports
FORWARD(GetFileVersionInfoA)
FORWARD(GetFileVersionInfoByHandle)
FORWARD(GetFileVersionInfoExA)
FORWARD(GetFileVersionInfoExW)
FORWARD(GetFileVersionInfoSizeA)
FORWARD(GetFileVersionInfoSizeExA)
FORWARD(GetFileVersionInfoSizeExW)
FORWARD(GetFileVersionInfoSizeW)
FORWARD(GetFileVersionInfoW)
FORWARD(VerFindFileA)
FORWARD(VerFindFileW)
FORWARD(VerInstallFileA)
FORWARD(VerInstallFileW)
FORWARD(VerLanguageNameA)
FORWARD(VerLanguageNameW)
FORWARD(VerQueryValueA)
FORWARD(VerQueryValueW)

// winmm.dll exports
FORWARD(CloseDriver)
FORWARD(DefDriverProc)
FORWARD(DriverCallback)
FORWARD(DrvGetModuleHandle)
FORWARD(GetDriverModuleHandle)
FORWARD(OpenDriver)
FORWARD(PlaySoundA)
FORWARD(PlaySoundW)
FORWARD(SendDriverMessage)
FORWARD(auxGetDevCapsA)
FORWARD(auxGetDevCapsW)
FORWARD(auxGetNumDevs)
FORWARD(auxGetVolume)
FORWARD(auxOutMessage)
FORWARD(auxSetVolume)
FORWARD(joyConfigChanged)
FORWARD(joyGetDevCapsA)
FORWARD(joyGetDevCapsW)
FORWARD(joyGetNumDevs)
FORWARD(joyGetPos)
FORWARD(joyGetPosEx)
FORWARD(joyGetThreshold)
FORWARD(joyReleaseCapture)
FORWARD(joySetCapture)
FORWARD(joySetThreshold)
FORWARD(mciDriverNotify)
FORWARD(mciDriverYield)
FORWARD(mciExecute)
FORWARD(mciFreeCommandResource)
FORWARD(mciGetCreatorTask)
FORWARD(mciGetDeviceIDA)
FORWARD(mciGetDeviceIDFromElementIDA)
FORWARD(mciGetDeviceIDFromElementIDW)
FORWARD(mciGetDeviceIDW)
FORWARD(mciGetDriverData)
FORWARD(mciGetErrorStringA)
FORWARD(mciGetErrorStringW)
FORWARD(mciGetYieldProc)
FORWARD(mciLoadCommandResource)
FORWARD(mciSendCommandA)
FORWARD(mciSendCommandW)
FORWARD(mciSendStringA)
FORWARD(mciSendStringW)
FORWARD(mciSetDriverData)
FORWARD(mciSetYieldProc)
FORWARD(midiConnect)
FORWARD(midiDisconnect)
FORWARD(midiInAddBuffer)
FORWARD(midiInClose)
FORWARD(midiInGetDevCapsA)
FORWARD(midiInGetDevCapsW)
FORWARD(midiInGetErrorTextA)
FORWARD(midiInGetErrorTextW)
FORWARD(midiInGetID)
FORWARD(midiInGetNumDevs)
FORWARD(midiInMessage)
FORWARD(midiInOpen)
FORWARD(midiInPrepareHeader)
FORWARD(midiInReset)
FORWARD(midiInStart)
FORWARD(midiInStop)
FORWARD(midiInUnprepareHeader)
FORWARD(midiOutCacheDrumPatches)
FORWARD(midiOutCachePatches)
FORWARD(midiOutClose)
FORWARD(midiOutGetDevCapsA)
FORWARD(midiOutGetDevCapsW)
FORWARD(midiOutGetErrorTextA)
FORWARD(midiOutGetErrorTextW)
FORWARD(midiOutGetID)
FORWARD(midiOutGetNumDevs)
FORWARD(midiOutGetVolume)
FORWARD(midiOutLongMsg)
FORWARD(midiOutMessage)
FORWARD(midiOutOpen)
FORWARD(midiOutPrepareHeader)
FORWARD(midiOutReset)
FORWARD(midiOutSetVolume)
FORWARD(midiOutShortMsg)
FORWARD(midiOutUnprepareHeader)
FORWARD(midiStreamClose)
FORWARD(midiStreamOpen)
FORWARD(midiStreamOut)
FORWARD(midiStreamPause)
FORWARD(midiStreamPosition)
FORWARD(midiStreamProperty)
FORWARD(midiStreamRestart)
FORWARD(midiStreamStop)
FORWARD(mixerClose)
FORWARD(mixerGetControlDetailsA)
FORWARD(mixerGetControlDetailsW)
FORWARD(mixerGetDevCapsA)
FORWARD(mixerGetDevCapsW)
FORWARD(mixerGetID)
FORWARD(mixerGetLineControlsA)
FORWARD(mixerGetLineControlsW)
FORWARD(mixerGetLineInfoA)
FORWARD(mixerGetLineInfoW)
FORWARD(mixerGetNumDevs)
FORWARD(mixerMessage)
FORWARD(mixerOpen)
FORWARD(mixerSetControlDetails)
FORWARD(mmDrvInstall)
FORWARD(mmGetCurrentTask)
FORWARD(mmTaskBlock)
FORWARD(mmTaskCreate)
FORWARD(mmTaskSignal)
FORWARD(mmTaskYield)
FORWARD(mmioAdvance)
FORWARD(mmioAscend)
FORWARD(mmioClose)
FORWARD(mmioCreateChunk)
FORWARD(mmioDescend)
FORWARD(mmioFlush)
FORWARD(mmioGetInfo)
FORWARD(mmioInstallIOProcA)
FORWARD(mmioInstallIOProcW)
FORWARD(mmioOpenA)
FORWARD(mmioOpenW)
FORWARD(mmioRead)
FORWARD(mmioRenameA)
FORWARD(mmioRenameW)
FORWARD(mmioSeek)
FORWARD(mmioSendMessage)
FORWARD(mmioSetBuffer)
FORWARD(mmioSetInfo)
FORWARD(mmioStringToFOURCCA)
FORWARD(mmioStringToFOURCCW)
FORWARD(mmioWrite)
FORWARD(mmsystemGetVersion)
FORWARD(sndPlaySoundA)
FORWARD(sndPlaySoundW)
FORWARD(timeBeginPeriod)
FORWARD(timeEndPeriod)
FORWARD(timeGetDevCaps)
FORWARD(timeGetSystemTime)
FORWARD(timeGetTime)
FORWARD(timeKillEvent)
FORWARD(timeSetEvent)
FORWARD(waveInAddBuffer)
FORWARD(waveInClose)
FORWARD(waveInGetDevCapsA)
FORWARD(waveInGetDevCapsW)
FORWARD(waveInGetErrorTextA)
FORWARD(waveInGetErrorTextW)
FORWARD(waveInGetID)
FORWARD(waveInGetNumDevs)
FORWARD(waveInGetPosition)
FORWARD(waveInMessage)
FORWARD(waveInOpen)
FORWARD(waveInPrepareHeader)
FORWARD(waveInReset)
FORWARD(waveInStart)
FORWARD(waveInStop)
FORWARD(waveInUnprepareHeader)
FORWARD(waveOutBreakLoop)
FORWARD(waveOutClose)
FORWARD(waveOutGetDevCapsA)
FORWARD(waveOutGetDevCapsW)
FORWARD(waveOutGetErrorTextA)
FORWARD(waveOutGetErrorTextW)
FORWARD(waveOutGetID)
FORWARD(waveOutGetNumDevs)
FORWARD(waveOutGetPitch)
FORWARD(waveOutGetPlaybackRate)
FORWARD(waveOutGetPosition)
FORWARD(waveOutGetVolume)
FORWARD(waveOutMessage)
FORWARD(waveOutOpen)
FORWARD(waveOutPause)
FORWARD(waveOutPrepareHeader)
FORWARD(waveOutReset)
FORWARD(waveOutRestart)
FORWARD(waveOutSetPitch)
FORWARD(waveOutSetPlaybackRate)
FORWARD(waveOutSetVolume)
FORWARD(waveOutUnprepareHeader)
FORWARD(waveOutWrite)

// dinput8.dll exports
FORWARD(DirectInput8Create)
FORWARD(DllCanUnloadNow)
FORWARD(DllGetClassObject)
FORWARD(DllRegisterServer)
FORWARD(DllUnregisterServer)
FORWARD(GetdfDIJoystick)
