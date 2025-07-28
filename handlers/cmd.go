package handlers

import (
	"fmt"
	"os/exec"
)

func ExecuteCMD(command string) string {
	if command == "" {
		return "❌ Use: !cmd <comando>"
	}
	cmd := exec.Command("cmd", "/C", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error executing cmd: %s\n%s", err.Error(), string(output))
	}
	return string(output)
}

func ExecutePowerShell(command string) string {
	if command == "" {
		return "❌ Use: !shell <comando>"
	}
	cmd := exec.Command("powershell", "-NoProfile", "-Command", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error executing powershell: %s\n%s", err.Error(), string(output))
	}
	return string(output)
}
