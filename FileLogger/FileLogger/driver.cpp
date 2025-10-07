#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")
#pragma comment(lib, "FltMgr.lib")

// Global filter handle
PFLT_FILTER gFilterHandle = NULL;

// Forward declarations
extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
NTSTATUS FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS PreCreateCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
FLT_POSTOP_CALLBACK_STATUS PostCreateCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);
FLT_POSTOP_CALLBACK_STATUS PostCleanupCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

// Helper function to check if this is our log file
BOOLEAN IsLogFile(PUNICODE_STRING FileName)
{
    UNICODE_STRING logFileName;
    RtlInitUnicodeString(&logFileName, L"\\hehe.txt");

    // Check if the filename ends with \hehe.txt
    if (FileName->Length >= logFileName.Length) {
        PWCH endOfPath = (PWCH)((PUCHAR)FileName->Buffer + FileName->Length - logFileName.Length);
        UNICODE_STRING ending;
        ending.Buffer = endOfPath;
        ending.Length = logFileName.Length;
        ending.MaximumLength = logFileName.Length;

        if (RtlCompareUnicodeString(&ending, &logFileName, TRUE) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

// Write to the logfile
NTSTATUS WriteToLogFile(PCWSTR Message)
{
    NTSTATUS status;
    HANDLE hFile;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    UNICODE_STRING filePath;
    RtlInitUnicodeString(&filePath, L"\\??\\C:\\Drivers\\hehe.txt");

    InitializeObjectAttributes(&objAttr, &filePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(
        &hFile,
        FILE_APPEND_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to open log file: 0x%X\n", status);
        return status;
    }

    // Write the message
    SIZE_T msgLen = wcslen(Message) * sizeof(WCHAR);
    status = ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatusBlock, (PVOID)Message, (ULONG)msgLen, NULL, NULL);

    // Write newline
    WCHAR newline[] = L"\r\n";
    ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatusBlock, newline, sizeof(newline) - sizeof(WCHAR), NULL, NULL);

    ZwClose(hFile);
    return status;
}

// Operations we want to filter
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreateCallback, PostCreateCallback },
    { IRP_MJ_CLEANUP, 0, NULL, PostCleanupCallback },
    { IRP_MJ_OPERATION_END }
};

// Filter registration
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),           // Size
    FLT_REGISTRATION_VERSION,            // Version
    0,                                   // Flags
    NULL,                                // Context
    Callbacks,                           // Operation callbacks
    FilterUnload,                        // Unload
    NULL,                                // InstanceSetup
    NULL,                                // InstanceQueryTeardown
    NULL,                                // InstanceTeardownStart
    NULL,                                // InstanceTeardownComplete
    NULL, NULL                           // NameProvider callbacks
};

// Pre-create callback
FLT_PREOP_CALLBACK_STATUS PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Only log file opens (not directory opens)
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Request post-operation callback
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// Post-create callback (file opened)
FLT_POSTOP_CALLBACK_STATUS PostCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);

        // Skip logging our own log file to prevent recursion
        if (nameInfo->Name.Length > 0 && !IsLogFile(&nameInfo->Name)) {
            WCHAR logMsg[512];
            RtlStringCbPrintfW(logMsg, sizeof(logMsg), L"File OPEN: %wZ", &nameInfo->Name);

            DbgPrint("%S\n", logMsg);
            WriteToLogFile(logMsg);
        }

        FltReleaseFileNameInformation(nameInfo);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// Post-cleanup callback (file closed)
FLT_POSTOP_CALLBACK_STATUS PostCleanupCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);

        // Skip logging our own log file to prevent recursion
        if (nameInfo->Name.Length > 0 && !IsLogFile(&nameInfo->Name)) {
            WCHAR logMsg[512];
            RtlStringCbPrintfW(logMsg, sizeof(logMsg), L"File CLOSE: %wZ", &nameInfo->Name);

            DbgPrint("%S\n", logMsg);
            WriteToLogFile(logMsg);
        }

        FltReleaseFileNameInformation(nameInfo);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// Unload routine
NTSTATUS FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    FltUnregisterFilter(gFilterHandle);
    DbgPrint("FileLogger minifilter unloaded.\n");

    return STATUS_SUCCESS;
}

// Driver entry point
extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("FileLogger minifilter loading...\n");

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);

    if (!NT_SUCCESS(status)) {
        DbgPrint("FltRegisterFilter failed: 0x%X\n", status);
        return status;
    }

    status = FltStartFiltering(gFilterHandle);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        DbgPrint("FltStartFiltering failed: 0x%X\n", status);
        return status;
    }

    DbgPrint("FileLogger minifilter started successfully.\n");
    return STATUS_SUCCESS;
}