#include <ntifs.h>
#include <wdm.h>

extern "C" {
    NTKERNELAPI NTSTATUS
    IoCreateDriver(
        _In_ PUNICODE_STRING DriverName,
        _In_ PDRIVER_INITIALIZE InitializationFunction
    );

    NTKERNELAPI NTSTATUS
    MmCopyVirtualMemory(
        _In_  PEPROCESS SourceProcess,
        _In_  PVOID     SourceAddress,
        _In_  PEPROCESS TargetProcess,
        _Out_ PVOID     TargetAddress,
        _In_  SIZE_T    BufferSize,
        _In_  KPROCESSOR_MODE PreviousMode,
        _Out_ PSIZE_T   ReturnSize
    );
}

VOID debug_print(PCSTR text) {
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s", text));
}

namespace driver {
    namespace codes {
        constexpr ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG read   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG write  = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
        constexpr ULONG detach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x699, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    }

    struct Request {
        HANDLE  process_id;
        PVOID   target;
        PVOID   buffer;
        SIZE_T  size;
        SIZE_T  return_size;
    };

    // Create: initialize FsContext to nullptr
    NTSTATUS create(PDEVICE_OBJECT /*device*/, PIRP irp) {
        auto stack = IoGetCurrentIrpStackLocation(irp);
        stack->FileObject->FsContext = nullptr;
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    // Close: dereference process if attached
    NTSTATUS close(PDEVICE_OBJECT /*device*/, PIRP irp) {
        auto stack = IoGetCurrentIrpStackLocation(irp);
        PFILE_OBJECT fileObj = stack->FileObject;
        if (fileObj->FsContext) {
            ObDereferenceObject(fileObj->FsContext);
            fileObj->FsContext = nullptr;
        }
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    // Lookup and store process reference
    NTSTATUS HandleAttach(Request* req, PEPROCESS& outProcess) {
        NTSTATUS status = PsLookupProcessByProcessId(req->process_id, &outProcess);
        if (!NT_SUCCESS(status)) {
            debug_print("[-] Attach failed");
        }
        return status;
    }

    // Copy virtual memory between processes
    NTSTATUS HandleReadWrite(
        PEPROCESS srcProc, PEPROCESS dstProc,
        PVOID src, PVOID dst,
        SIZE_T size, PSIZE_T outSize,
        BOOLEAN isRead
    ) {
        // Validate user-mode pointers if necessary (for METHOD_NEITHER)
        if (isRead) {
            ProbeForWrite(dst, size, sizeof(UCHAR));
        } else {
            ProbeForRead(src, size, sizeof(UCHAR));
        }

        return MmCopyVirtualMemory(
            srcProc, src,
            dstProc, dst,
            size, KernelMode,
            outSize
        );
    }

    NTSTATUS device_control(PDEVICE_OBJECT /*device*/, PIRP irp) {
        auto stack = IoGetCurrentIrpStackLocation(irp);
        Request* req = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);
        NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
        SIZE_T bytesTransferred = 0;

        if (!stack || !req) {
            debug_print("[-] Invalid IRP or buffer");
            status = STATUS_INVALID_PARAMETER;
            goto complete;
        }

        ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
        PFILE_OBJECT fileObj = stack->FileObject;

        switch (code) {
        case codes::attach: {
            PEPROCESS proc = nullptr;
            status = HandleAttach(req, proc);
            if (NT_SUCCESS(status)) {
                // Store the reference for later read/write/detach
                fileObj->FsContext = proc;
            }
            break;
        }

        case codes::detach: {
            auto proc = static_cast<PEPROCESS>(fileObj->FsContext);
            if (proc) {
                ObDereferenceObject(proc);
                fileObj->FsContext = nullptr;
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_NOT_FOUND;
                debug_print("[-] No process to detach");
            }
            break;
        }

        case codes::read:
        case codes::write: {
            auto proc = static_cast<PEPROCESS>(fileObj->FsContext);
            if (!proc) {
                debug_print("[-] No process attached");
                status = STATUS_PROCESS_IS_TERMINATING;
                break;
            }

            BOOLEAN isRead = (code == codes::read);
            PEPROCESS srcProc = isRead ? proc : PsGetCurrentProcess();
            PEPROCESS dstProc = isRead ? PsGetCurrentProcess() : proc;
            PVOID    srcAddr = isRead ? req->target : req->buffer;
            PVOID    dstAddr = isRead ? req->buffer : req->target;

            status = HandleReadWrite(
                srcProc, dstProc,
                srcAddr, dstAddr,
                req->size, &bytesTransferred,
                isRead
            );

            if (!NT_SUCCESS(status)) {
                debug_print(isRead ? "[-] Read failed" : "[-] Write failed");
            }
            break;
        }

        default:
            debug_print("[-] Unknown IOCTL");
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }

    complete:
        irp->IoStatus.Status = status;
        irp->IoStatus.Information = NT_SUCCESS(status) ? bytesTransferred : 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return status;
    }
}

// Unload: cleanup symbolic link and device
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING sym = RTL_CONSTANT_STRING(L"\\DosDevices\\TSCDriver");
    IoDeleteSymbolicLink(&sym);
    IoDeleteDevice(DriverObject->DeviceObject);
    debug_print("[+] Driver unloaded");
}

// Main initialization: create device, symlink, set dispatch routines
NTSTATUS driver_main(PDRIVER_OBJECT DriverObject, PUNICODE_STRING /*RegistryPath*/) {
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\TSCDriver");
    PDEVICE_OBJECT deviceObject = nullptr;
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        debug_print("[-] Failed to create device");
        return status;
    }
    debug_print("[+] Device created");

    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\TSCDriver");
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        debug_print("[-] Failed to create symbolic link");
        IoDeleteDevice(deviceObject);
        return status;
    }
    debug_print("[+] Symbolic link created");

    SetFlag(deviceObject->Flags, DO_BUFFERED_IO);

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = driver::create;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = driver::close;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;
    DriverObject->DriverUnload                         = DriverUnload;

    ClearFlag(deviceObject->Flags, DO_DEVICE_INITIALIZING);
    debug_print("[+] Driver initialized");

    return STATUS_SUCCESS;
}

// Entry point
extern "C" NTSTATUS DriverEntry() {
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Driver\\TSCDriver");
    debug_print("[+] DriverEntry started");
    return IoCreateDriver(&name, driver_main);
}
