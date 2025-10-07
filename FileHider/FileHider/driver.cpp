#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntstrsafe.h>

#pragma comment(lib, "FltMgr.lib")

// Global filter handle
PFLT_FILTER gFilterHandle = NULL;

// Forward declarations
extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
NTSTATUS FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS PreCreateCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS PreDirectoryControlCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _Flt_CompletionContext_Outptr_ PVOID* CompletionContext);
FLT_POSTOP_CALLBACK_STATUS PostDirectoryControlCallback(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

// function to check if filename starts with "secret"
BOOLEAN IsSecretFile(PUNICODE_STRING FileName)
{
    UNICODE_STRING secretPrefix;
    RtlInitUnicodeString(&secretPrefix, L"secret");

    // just the filename (after last backslash)
    PWCH lastBackslash = NULL;
    for (USHORT i = 0; i < FileName->Length / sizeof(WCHAR); i++) {
        if (FileName->Buffer[i] == L'\\') {
            lastBackslash = &FileName->Buffer[i + 1];
        }
    }

    UNICODE_STRING actualFileName;
    if (lastBackslash) {
        actualFileName.Buffer = lastBackslash;
        actualFileName.Length = (USHORT)((FileName->Buffer + (FileName->Length / sizeof(WCHAR))) - lastBackslash) * sizeof(WCHAR);
        actualFileName.MaximumLength = actualFileName.Length;
    }
    else {
        actualFileName = *FileName;
    }

    // Check if filename starts with "secret" (case-insensitive)
    if (actualFileName.Length >= secretPrefix.Length) {
        UNICODE_STRING filePrefix;
        filePrefix.Buffer = actualFileName.Buffer;
        filePrefix.Length = secretPrefix.Length;
        filePrefix.MaximumLength = secretPrefix.Length;

        if (RtlCompareUnicodeString(&filePrefix, &secretPrefix, TRUE) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

// check if a directory entry starts with "secret"
BOOLEAN IsSecretEntry(PUNICODE_STRING EntryName)
{
    UNICODE_STRING secretPrefix;
    RtlInitUnicodeString(&secretPrefix, L"secret");

    if (EntryName->Length >= secretPrefix.Length) {
        UNICODE_STRING entryPrefix;
        entryPrefix.Buffer = EntryName->Buffer;
        entryPrefix.Length = secretPrefix.Length;
        entryPrefix.MaximumLength = secretPrefix.Length;

        if (RtlCompareUnicodeString(&entryPrefix, &secretPrefix, TRUE) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

// Operations we want to filter
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreateCallback, NULL },
    { IRP_MJ_DIRECTORY_CONTROL, 0, PreDirectoryControlCallback, PostDirectoryControlCallback },
    { IRP_MJ_OPERATION_END }
};

// Filter registration
CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    FilterUnload,
    NULL, NULL, NULL, NULL,
    NULL, NULL
};

// Pre-create callback: blocks access to files starting with "secret"
FLT_PREOP_CALLBACK_STATUS PreCreateCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);

    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);

        // Check if is a secret file
        if (IsSecretFile(&nameInfo->Name)) {
            DbgPrint("FileHider: Blocking access to: %wZ\n", &nameInfo->Name);

            // make file invisible
            Data->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
            Data->IoStatus.Information = 0;

            FltReleaseFileNameInformation(nameInfo);

            // Complete the IRP without passing it down
            FltCompletePendedPreOperation(Data, FLT_PREOP_COMPLETE, NULL);
            return FLT_PREOP_COMPLETE;
        }

        FltReleaseFileNameInformation(nameInfo);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// Pre-directory control callback
FLT_PREOP_CALLBACK_STATUS PreDirectoryControlCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Only handle directory query operations
    if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // Requests post-operation callback to filter our results
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

// Post-directory control callback - removes "secret" files from directory listings
FLT_POSTOP_CALLBACK_STATUS PostDirectoryControlCallback(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    // Only process successful directory queries
    if (!NT_SUCCESS(Data->IoStatus.Status) ||
        Data->IoStatus.Information == 0 ||
        FLT_IS_FASTIO_OPERATION(Data)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Can't process at DPC level
    if (FLTFL_POST_OPERATION_DRAINING & Flags) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    PVOID buffer = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
    if (buffer == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;

    PVOID currentEntry = buffer;
    PVOID prevEntry = NULL;

    while (currentEntry != NULL) {
        PULONG nextOffset = NULL;
        PULONG fileNameLength = NULL;
        PWCHAR fileName = NULL;

        // Get pointers based on information class
        switch (infoClass) {
        case FileDirectoryInformation: {
            PFILE_DIRECTORY_INFORMATION dirInfo = (PFILE_DIRECTORY_INFORMATION)currentEntry;
            nextOffset = &dirInfo->NextEntryOffset;
            fileNameLength = &dirInfo->FileNameLength;
            fileName = dirInfo->FileName;
            break;
        }
        case FileFullDirectoryInformation: {
            PFILE_FULL_DIR_INFORMATION fullInfo = (PFILE_FULL_DIR_INFORMATION)currentEntry;
            nextOffset = &fullInfo->NextEntryOffset;
            fileNameLength = &fullInfo->FileNameLength;
            fileName = fullInfo->FileName;
            break;
        }
        case FileBothDirectoryInformation: {
            PFILE_BOTH_DIR_INFORMATION bothInfo = (PFILE_BOTH_DIR_INFORMATION)currentEntry;
            nextOffset = &bothInfo->NextEntryOffset;
            fileNameLength = &bothInfo->FileNameLength;
            fileName = bothInfo->FileName;
            break;
        }
        case FileNamesInformation: {
            PFILE_NAMES_INFORMATION namesInfo = (PFILE_NAMES_INFORMATION)currentEntry;
            nextOffset = &namesInfo->NextEntryOffset;
            fileNameLength = &namesInfo->FileNameLength;
            fileName = namesInfo->FileName;
            break;
        }
        default:
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        // Check if this entry should be hidden
        UNICODE_STRING fileNameStr;
        fileNameStr.Buffer = fileName;
        fileNameStr.Length = (USHORT)*fileNameLength;
        fileNameStr.MaximumLength = (USHORT)*fileNameLength;

        BOOLEAN shouldHide = IsSecretEntry(&fileNameStr);

        if (shouldHide) {
            DbgPrint("FileHider: Hiding from directory: %wZ\n", &fileNameStr);

            if (*nextOffset == 0) {
                // Last entry in the list
                if (prevEntry != NULL) {
                    PULONG prevNextOffset = NULL;

                    switch (infoClass) {
                    case FileDirectoryInformation:
                        prevNextOffset = &((PFILE_DIRECTORY_INFORMATION)prevEntry)->NextEntryOffset;
                        break;
                    case FileFullDirectoryInformation:
                        prevNextOffset = &((PFILE_FULL_DIR_INFORMATION)prevEntry)->NextEntryOffset;
                        break;
                    case FileBothDirectoryInformation:
                        prevNextOffset = &((PFILE_BOTH_DIR_INFORMATION)prevEntry)->NextEntryOffset;
                        break;
                    case FileNamesInformation:
                        prevNextOffset = &((PFILE_NAMES_INFORMATION)prevEntry)->NextEntryOffset;
                        break;
                    }

                    if (prevNextOffset) {
                        *prevNextOffset = 0;
                    }
                }
                else {
                    // Only entry in the list
                    Data->IoStatus.Status = STATUS_NO_MORE_FILES;
                    Data->IoStatus.Information = 0;
                }
                break;
            }
            else {
                // Not the last entry
                ULONG nextEntryOffset = *nextOffset;

                if (prevEntry != NULL) {
                    // Link previous entry to next entry
                    PULONG prevNextOffset = NULL;

                    switch (infoClass) {
                    case FileDirectoryInformation:
                        prevNextOffset = &((PFILE_DIRECTORY_INFORMATION)prevEntry)->NextEntryOffset;
                        break;
                    case FileFullDirectoryInformation:
                        prevNextOffset = &((PFILE_FULL_DIR_INFORMATION)prevEntry)->NextEntryOffset;
                        break;
                    case FileBothDirectoryInformation:
                        prevNextOffset = &((PFILE_BOTH_DIR_INFORMATION)prevEntry)->NextEntryOffset;
                        break;
                    case FileNamesInformation:
                        prevNextOffset = &((PFILE_NAMES_INFORMATION)prevEntry)->NextEntryOffset;
                        break;
                    }

                    if (prevNextOffset) {
                        *prevNextOffset += nextEntryOffset;
                    }
                }
                else {
                    // First entry is being removed
                    PVOID nextEntry = (PUCHAR)currentEntry + nextEntryOffset;
                    SIZE_T remainingSize = Data->IoStatus.Information - nextEntryOffset;

                    RtlMoveMemory(currentEntry, nextEntry, remainingSize);
                    Data->IoStatus.Information -= nextEntryOffset;

                    // Don't update prevEntry, check the same position again
                    continue;
                }

                // Move to next entry
                currentEntry = (PUCHAR)currentEntry + nextEntryOffset;
                continue;
            }
        }

        // Entry is not being hidden, it becomes the new previous
        prevEntry = currentEntry;

        // Move to next entry
        if (*nextOffset == 0) {
            break;
        }

        currentEntry = (PUCHAR)currentEntry + *nextOffset;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

// Unload routine
NTSTATUS FilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    FltUnregisterFilter(gFilterHandle);
    DbgPrint("FileHider minifilter unloaded.\n");

    return STATUS_SUCCESS;
}

// Driver entry point
extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrint("FileHider Started\n");
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

    DbgPrint("FileHider minifilter started successfully.\n");
    DbgPrint("All files starting with 'secret' are now hidden!\n");

    return STATUS_SUCCESS;
}