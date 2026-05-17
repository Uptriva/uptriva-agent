package main

import (
	"encoding/json"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetSystemTimes           = modkernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx     = modkernel32.NewProc("GlobalMemoryStatusEx")
	procGetDiskFreeSpaceExW      = modkernel32.NewProc("GetDiskFreeSpaceExW")
	procCreateToolhelp32Snapshot = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = modkernel32.NewProc("Process32FirstW")
	procProcess32NextW           = modkernel32.NewProc("Process32NextW")
)

type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

type processEntry32W struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260]uint16
}

func readProcStat() (uint64, uint64, error) {
	var idleTime, kernelTime, userTime syscall.Filetime
	r, _, err := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idleTime)),
		uintptr(unsafe.Pointer(&kernelTime)),
		uintptr(unsafe.Pointer(&userTime)),
	)
	if r == 0 {
		return 0, 0, err
	}

	idle := (uint64(idleTime.HighDateTime) << 32) + uint64(idleTime.LowDateTime)
	kernel := (uint64(kernelTime.HighDateTime) << 32) + uint64(kernelTime.LowDateTime)
	user := (uint64(userTime.HighDateTime) << 32) + uint64(userTime.LowDateTime)

	total := kernel + user
	return total, idle, nil
}

func readRAMUsage() (float64, error) {
	var ms memoryStatusEx
	ms.dwLength = uint32(unsafe.Sizeof(ms))
	r, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	if r == 0 {
		return 0, err
	}
	total := ms.ullTotalPhys
	avail := ms.ullAvailPhys
	if total == 0 {
		return 0, fmt.Errorf("zero total memory")
	}
	return (float64(total-avail) / float64(total)) * 100, nil
}

func readDiskUsage() (float64, error) {
	var freeBytes, totalBytes, totalFreeBytes uint64
	path, err := syscall.UTF16PtrFromString("C:\\")
	if err != nil {
		return 0, err
	}
	r, _, err := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(path)),
		uintptr(unsafe.Pointer(&freeBytes)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFreeBytes)),
	)
	if r == 0 {
		return 0, err
	}
	if totalBytes == 0 {
		return 0, fmt.Errorf("zero disk size")
	}
	used := totalBytes - totalFreeBytes
	return (float64(used) / float64(totalBytes)) * 100, nil
}

func readNetworkBytes() (int64, int64, error) {
	return 0, 0, nil
}

func readRunningProcesses() (string, error) {
	var th32csSnapProcess uintptr = 0x00000002
	hSnap, _, err := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if syscall.Handle(hSnap) == syscall.InvalidHandle {
		return "[]", err
	}
	defer syscall.CloseHandle(syscall.Handle(hSnap))

	var pe processEntry32W
	pe.dwSize = uint32(unsafe.Sizeof(pe))

	r, _, _ := procProcess32FirstW.Call(hSnap, uintptr(unsafe.Pointer(&pe)))
	if r == 0 {
		return "[]", fmt.Errorf("failed first process")
	}

	var list []string
	for {
		name := syscall.UTF16ToString(pe.szExeFile[:])
		if name != "" {
			list = append(list, name)
		}
		pe.dwSize = uint32(unsafe.Sizeof(pe))
		r, _, _ = procProcess32NextW.Call(hSnap, uintptr(unsafe.Pointer(&pe)))
		if r == 0 {
			break
		}
	}

	b, err := json.Marshal(list)
	if err != nil {
		return "[]", err
	}
	return string(b), nil
}
