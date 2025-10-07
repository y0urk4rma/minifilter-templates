// usermode.c - Test application for FileLogger minifilter
#include <windows.h>
#include <stdio.h>

int main() {
    const wchar_t* fileName = L"testfile.txt";  // File in the same folder as exe

    printf("FileLogger Minifilter Test\n");
    printf("===========================\n\n");
    printf("The minifilter will automatically log all file opens/closes.\n");
    printf("Check C:\\Drivers\\hehe.txt for the log output.\n\n");

    for (int i = 0; i < 3; i++) {
        printf("Iteration %d:\n", i + 1);

        // Create/Open the file
        HANDLE hFile = CreateFileW(
            fileName,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,    // Create new or overwrite existing
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            printf("  Failed to create/open %S. Error: %lu\n", fileName, GetLastError());
        } else {
            printf("  ✓ File opened: %S\n", fileName);
            
            // Write some data
            const char* data = "Hello from usermode!\n";
            DWORD bytesWritten;
            WriteFile(hFile, data, (DWORD)strlen(data), &bytesWritten, NULL);
            printf("  ✓ Wrote %lu bytes\n", bytesWritten);
            
            // Close the file
            CloseHandle(hFile);
            printf("  ✓ File closed\n");
        }

        printf("\n");
        Sleep(500);  // Small delay between iterations
    }

    // Also test opening an existing file
    printf("Opening an existing file...\n");
    HANDLE hFile = CreateFileW(
        fileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        printf("  ✓ Opened existing file for reading\n");
        
        // Read the data back
        char buffer[256] = {0};
        DWORD bytesRead;
        ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
        printf("  ✓ Read %lu bytes: %s", bytesRead, buffer);
        
        CloseHandle(hFile);
        printf("  ✓ File closed\n");
    }

    printf("\n===========================\n");
    printf("Test completed!\n");
    printf("Check the log file at: C:\\Drivers\\hehe.txt\n");
    printf("Or use DebugView to see DbgPrint output.\n");

    return 0;
}