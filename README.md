# Kernel Driver Cheat Bridge
This repository hosts a kernel driver designed to bypass kernel-level anti-cheats.

## Usage
If you're here, you probably know what you're doing.

The driver is registered with the name "TSCDriver," but you can modify this in the source code if necessary.

Using any Kernel Driver mapper can work, such as kdmapper.

## Getting the Driver Handle
Use the following code snippet to obtain the driver handle:
```cpp
const HANDLE driver_handle = CreateFileW(L"\\\\.\\TSCDriver", GENERIC_READ | GENERIC_WRITE,
  FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
  FILE_ATTRIBUTE_NORMAL, nullptr);

if (driver::attach_to_process(driver_handle, pid)) {
	std::cout << "[+] Attached to process" << std::endl;
}
```

## Example Userland Client
Below is an example of a userland client:
```cpp
namespace driver {
	namespace codes {
		constexpr ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	}

	struct Request {
		HANDLE process_id;

		PVOID target;
		PVOID buffer;

		SIZE_T size;
		SIZE_T return_size;
	};

	bool attach_to_process(HANDLE driver_handle, const DWORD pid) {
		Request request;
		request.process_id = reinterpret_cast<HANDLE>(pid);

		return DeviceIoControl(driver_handle, codes::attach, &request, sizeof(request), nullptr, sizeof(request), nullptr, nullptr);
	}

	template <class T>
	T read_memory(HANDLE driver_handle, const std::uintptr_t address) {
		T temp = {};
		Request request;
		request.target = reinterpret_cast<PVOID>(address);
		request.buffer = &temp;
		request.size = sizeof(T);

		DeviceIoControl(driver_handle, codes::read, &request, sizeof(request), &request, sizeof(request), nullptr, nullptr);

		return temp;
	}

	template <class T>
	void write_memory(HANDLE driver_handle, const std::uintptr_t address, const T& value) {
		Request r;
		r.target = reinterpret_cast<PVOID>(address);
		r.buffer = (PVOID) &value;
		r.size = sizeof(T);

		DeviceIoControl(driver_handle, codes::write, &r, sizeof(r), nullptr, sizeof(r), nullptr, nullptr);

	}
}
```

Feel free to adjust and integrate this code into your project as needed.
