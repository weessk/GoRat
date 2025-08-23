# Go Rat (BETA)
![GitHub stars](https://img.shields.io/github/stars/weessk/GoolangRat-C2?style=social)
![Forks](https://img.shields.io/github/forks/weessk/GoolangRat-C2?style=social)

New Discord RAT & Stealer. Made with Go so it's small, fast, and doesn't eat all the RAM.

**This is a BETA version.** It means it works, but I might add more evil shit later. Or maybe I'll get bored and abandon it. Who knows.

## ⚠️ Don't Be A Dumbass (Disclaimer)
This is for "education". If you get your ass thrown in jail for using this on your school's computers, that's 100% on you. I just write code.

---
## 🔥 Features
- **Remote Shell:** Full `cmd` and `powershell` access.
- **Privilege Escalation:** Uacbypass commands and system elevate commands!
- **Rootkit stuffs**: PEB unlinking, API hooking, and name spoofing
- **Discord C2:** Control everything from a Discord server.
- **Persistence:** Tries its best to stay alive after a reboot.
- **Data Stealing:** Grabs Discord tokens and browser data.
- **Live Surveillance:** `!screen` command to see what they see.
- **Self-Destruct:** `!exit` command to wipe all traces.
- **🔥 TINY:** The final `.exe` is **under 3MB**. Easy to spread.

📜 **Changelog:** [see latest updates](./CHANGELOG.md)

## 🤔 Is It FUD? (Detection Status)
a quick reality check, dumbass
right now, this is more of a poc than a production weapon. why? no fucking obfuscation (only basic upx-mod).
the compiled binary is 'naked'. any security nerd can pop it open in IDA and see all the juicy function names (BypassUAC, namedPipeImpersonation, etc) and strings. that's why this thing has a short shelf life.

*   **Right now? It's SEMI-FUD.** It shits on a lot of basic AVs.
*   **In 2 weeks? It'll be flagged to hell.** Once this gets a few stars, security nerds will write signatures for it.

So yeah, **use it while it's hot.**

### Proof (as of right now):
![proof](https://i.ibb.co/yFS4Gxzm/image.png)

---

## 🛠️ How to Build (It's Fucking Easy)
I made it impossible for you to fuck this up.

1.  **Install Go.** If you don't know how, google it. [Here's a link, lazy ass.](https://golang.org/dl/)
2.  **Run the Builder.**
    *   Just double-click `build.bat`. Everything else is included in the repo.
    *   It will ask for your **Bot Token** and **Server ID**. Don't fuck it up. Paste them and press Enter.
3.  **Done.**
    *   Look for `WinSecurityHealth.exe`. That's your new toy.

## 🤖 Commands
Use these in the victim's channel on Discord.

| Category                  | Command            | Description                                                    |
| ------------------------- | ------------------ | -------------------------------------------------------------- |
| **SYSTEM & CONTROL**      | `!help`            | Shows this command list, duh.                                  |
|                           | `!privs`           | Checks your privileges (admin? system? peasant?).              |
|                           | `!cmd <command>`   | Runs a CMD command.                                            |
|                           | `!shell <command>` | Runs a PowerShell command.                                     |
|                           | `!screen`          | Takes a pic of their screen.                                   |
|                           | `!exit`            | **PANIC BUTTON.** Nukes itself from orbit.                     |
| **DATA STEALING**         | `!tokengrab`       | Steals Discord tokens.                                         |
|                           | `!browser`         | Steals browser data (passwords, cookies, etc).                 |
| **PRIVILEGE ESCALATION**  | `!admin [method]`  | Classic UAC bypass. Leave blank to fire all cannons.           |
|                           | `!system [method]` | Go for god mode (`NT AUTHORITY\SYSTEM`). Requires admin first. |
| **STEALTH & PERSISTENCE** | `!hide [method]`   | Become a ghost. Methods: `peb`, `hook`, `spoof`, `all`.        |
|                           | `!stealth`         | Checks which stealth features are active.                      |
|                           | `!persistence`     | Makes sure the RAT survives a reboot.                          |

---
*Have fun.*
