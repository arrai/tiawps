#include <iostream>
#include <windows.h>
#include <fstream>
#include <winsock.h>
#include <ws2tcpip.h>


#define CONNECTION_PTR_OFFSET      0x00C923C0
#define SESSIONKEY_OFFSET          0x508
#define VERSION                    "3.2.2"
#define CONFIG_NAME                "tiawps_reader_config.txt"
#define SESSIONKEY_LENGTH          40
struct Config
{
    std::string tiawpsHost;
    std::string tiawpsPort;

    bool readConfig(char* fileName)
    {
        std::ifstream inFile;
        inFile.open(CONFIG_NAME);
        if(!inFile)
        {
            printf("Couldn't open config file %s\n", fileName);
            return false;
        }
        if (inFile >> tiawpsHost &&
            inFile >> tiawpsPort)
        {
            printf("loaded config: host = %s, port = %s\n",
                tiawpsHost.c_str(), tiawpsPort.c_str());
            int tiawpsPort = atoi(this->tiawpsPort.c_str());
            if(tiawpsPort < 0 || tiawpsPort > 0xFFFF)
            {
                printf("invalid port %u!\n", tiawpsPort);
                return false;
            }
            return true;
        }
        return false;
    }
};

void dumpByteArray(char* array, int size)
{
     for(int i=0; i<size;i++)
         printf("%02X ", (unsigned char)array[i]);
}

void sendToTiawps(Config const& config, char* sessionKey)
{
     WSADATA wsaData;
     SOCKET ConnectSocket = INVALID_SOCKET;
     struct addrinfo *result = NULL, *ptr = NULL, hints;
     
     int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
     if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return;
    }
    ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    iResult = getaddrinfo(config.tiawpsHost.c_str(), config.tiawpsPort.c_str(), &hints, &result);
    if ( iResult != 0 ) {
        printf("getaddrinfo failed: %d\n", iResult);
        WSACleanup();
        return;
    }

    for(ptr=result; ptr != NULL ;ptr=ptr->ai_next)
    {
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, 
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("Error at socket(): %ld\n", WSAGetLastError());
            freeaddrinfo(result);
            WSACleanup();
            return;
        }
        iResult = connect( ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }
    freeaddrinfo(result);
    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to tiawps!\n");
        WSACleanup();
        return;
    }
    int sendBufSize = SESSIONKEY_LENGTH;
    char* sendbuf = new char[sendBufSize];
    memset(sendbuf, 0, sendBufSize);
    memcpy(sendbuf, sessionKey, SESSIONKEY_LENGTH);
    iResult = send( ConnectSocket, sendbuf, sendBufSize, 0 );
    if (iResult == SOCKET_ERROR) {
        printf("send failed: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return;
    }
    printf("Bytes Sent: %ld\n", iResult);
    closesocket(ConnectSocket);
    WSACleanup();
}

bool readSessionKey(char* sessionKey)
{
    HANDLE hToken;
    OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken );
    
    TOKEN_PRIVILEGES tp = { 0 }; 
    LUID luid; 
    DWORD cb = sizeof(TOKEN_PRIVILEGES); 
    if( !LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &luid ) )
        return false;

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
        return false;
    }

    GetWindowThreadProcessId(WindowsHandle, &WindowsPID);
    HANDLE wow_process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, WindowsPID);
    
    DWORD number_of_read_bytes=0;
    
    char pointer[4] = {'\0'};
    ReadProcessMemory(wow_process_handle, (LPCVOID)CONNECTION_PTR_OFFSET, pointer, 4, &number_of_read_bytes); 
    
    if(number_of_read_bytes != 4)
    {
        printf("couldn't read pointer, just read %u bytes instead of 4\n", number_of_read_bytes);
        CloseHandle(wow_process_handle);
        return false;
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
        return false;
    }
    printf("Got sessionkey: ");
    dumpByteArray(sessionKey, SESSIONKEY_LENGTH);
    printf("\n");

    printf("checking plausibility\n");
    bool foundNonZero = false;
    for(int i=0; i< SESSIONKEY_LENGTH; i++)
        if(sessionKey[i]!=0)
            foundNonZero=true;

    if(!foundNonZero)
    {
        printf("sessionKey contains only of zeros - unlikely..\n");
        return false;
    }

    return true;
}
int main()
{
    printf("Tiawps sessionkey reader for version %s started\n", VERSION);
    printf("loading config\n");
    Config cfg;
    if(!cfg.readConfig(CONFIG_NAME))
        return 1;

    char sessionKey[SESSIONKEY_LENGTH] = {'\0'};

   while(!readSessionKey(sessionKey))
   {
       printf("reading sessionkey failed - will try again in 1 second\n");
       Sleep(1000);
   }
    
    printf("trying to send it to tiawps dumper\n");
    sendToTiawps(cfg, sessionKey);

    return 0;
}

