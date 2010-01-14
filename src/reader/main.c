#include <windows.h>
#include <stdio.h>

#define CONNECTION_PTR_OFFSET      0x00C923C0
#define SESSIONKEY_OFFSET          0x508
#define VERSION                    "Build 11159 3.3.x"
#define SESSIONKEY_LENGTH          40

void dumpByteArray(char* array, int size)
{
    for(int i=0; i<size;i++)
        printf("%02X ", (unsigned char)array[i]);
}

_Bool readSessionKey(char* sessionKey)
{
    HANDLE hToken;
    OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken );

    TOKEN_PRIVILEGES tp = { 0 }; 
    LUID luid; 
    DWORD cb = sizeof(TOKEN_PRIVILEGES); 
    if( !LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &luid ) )
        return FALSE;

    tp.PrivilegeCount = 1; 
    tp.Privileges[0].Luid = luid; 
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges( hToken, FALSE, &tp, cb, NULL, NULL );
    CloseHandle(hToken);

    unsigned long WindowsPID;

    char applicationName[] = "World of Warcraft";

    HWND WindowsHandle = FindWindow(0, applicationName);
    if (!WindowsHandle)
    {
        printf("Window %s not found!\n", applicationName);
        return FALSE;
    }

    GetWindowThreadProcessId(WindowsHandle, &WindowsPID);
    HANDLE wow_process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, WindowsPID);

    DWORD number_of_read_bytes=0;

    char pointer[4] = {'\0'};
    ReadProcessMemory(wow_process_handle, (LPCVOID)CONNECTION_PTR_OFFSET, pointer, 4, &number_of_read_bytes); 

    if(number_of_read_bytes != 4)
    {
        printf("couldn't read pointer, just read %u bytes instead of 4\n", number_of_read_bytes);
        CloseHandle(wow_process_handle);
        return FALSE;
    }
    // convert bytes to pointer
    unsigned int sessionKeyPosition = 0;
    memcpy(&sessionKeyPosition, pointer, 4);
    printf("Got pointer: %#X\n", sessionKeyPosition);

    number_of_read_bytes = 0;
    ReadProcessMemory(wow_process_handle, (LPCVOID)(SESSIONKEY_OFFSET+sessionKeyPosition), sessionKey, SESSIONKEY_LENGTH, &number_of_read_bytes);
    CloseHandle(wow_process_handle);
    if(number_of_read_bytes != SESSIONKEY_LENGTH)
    {
        printf("couldn't read sessionkey, read %u bytes instaed of %u\n", number_of_read_bytes, SESSIONKEY_LENGTH);
        return FALSE;
    }
    printf("Got sessionkey: ");
    dumpByteArray(sessionKey, SESSIONKEY_LENGTH);
    printf("\n");

    printf("checking plausibility\n");
    _Bool foundNonZero = FALSE;
    for(int i=0; i< SESSIONKEY_LENGTH; i++)
        if(sessionKey[i]!=0)
            foundNonZero=TRUE;

    if(!foundNonZero)
    {
        printf("sessionKey contains only of zeros - unlikely..\n");
        return FALSE;
    }

    return TRUE;
}

int main()
{
    printf("Tiawps sessionkey reader for version %s started\n", VERSION);
    
    char sessionKey[SESSIONKEY_LENGTH] = {'\0'};

    while(!readSessionKey(sessionKey))
    {
        printf("reading sessionkey failed - will try again in 1 second\n");
        Sleep(1000);
    }

    printf("trying to send it to tiawps dumper\n");

    return 0;
}

