package handlers

import (
	"fmt"
	"image/png"
	"os"
	"path/filepath"

	"github.com/kbinani/screenshot"
)

func TakeScreenshot() (string, error) {
	bounds := screenshot.GetDisplayBounds(0)
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		return "", fmt.Errorf("❌ the screen could not be captured: %v", err)
	}

	filePath := filepath.Join(os.TempDir(), "capture.png")
	file, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("❌ the temporary file could not be created: %v", err)
	}
	defer file.Close()

	err = png.Encode(file, img)
	if err != nil {
		return "", fmt.Errorf("❌ the image could not be encoded to png: %v", err)
	}

	return filePath, nil
}
