# Go Rat
![GitHub stars](https://img.shields.io/github/stars/weessk/GoolangRat-C2?style=social)
![Forks](https://img.shields.io/github/forks/weessk/GoolangRat-C2?style=social)

A Remote Administration Tool & Stealer developed in Go. It utilizes Discord for command and control (C2), offering a lightweight and efficient solution for remote system management and data gathering.

**Current Status: BETA.** The tool is functional but under active development. Features may be added or changed.

---
## Features
- **Remote Shell:** Full command-line access via `cmd` and `powershell`.
- **Privilege Escalation:** Includes methods for UAC bypass and elevation to `NT AUTHORITY\SYSTEM`.
- **Stealth Capabilities:** Implements PEB unlinking, API hooking, and process name spoofing to evade detection.
- **Discord C2:** All operations are managed through a discreet Discord server.
- **Persistence:** Employs techniques to ensure the agent survives system reboots.
- **Data Exfiltration:** Capable of extracting Discord tokens and sensitive browser data (credentials, cookies).
- **Live Surveillance:** Real-time desktop screenshot capture.
- **Self-Destruct:** A kill-switch command to remove all traces of the agent from the target system.
- **Compact Payload:** The compiled executable is under 3MB.

📜 **Changelog:** [See latest updates](./CHANGELOG.md)

## Detection Status
This is a proof-of-concept and does not include advanced obfuscation or encryption beyond a modified UPX packer. The compiled binary is unobfuscated, meaning its functions and strings are easily identifiable with reverse engineering tools.

-   **Initial State:** The payload has a low detection rate against many standard antivirus solutions.
-   **Expected Lifespan:** As a public tool, it will likely be fingerprinted by security vendors and detection rates will increase significantly over time.

---

## Build Instructions

### Prerequisites
-   Go (Golang) compiler installed and configured.

### Building
1.  Clone the repository.
2.  Execute the `build.bat` script.
3.  The script will prompt you to enter your Discord **Bot Token** and **Server ID**.
4.  Upon successful compilation, the output file `WinSecurityHealth.exe` will be created in the project directory.

## Commands
All commands are executed within the corresponding bot channel on your Discord server.

| Category                  | Command            | Description                                                              |
| ------------------------- | ------------------ | ------------------------------------------------------------------------ |
| **System & Control**      | `!help`            | Displays the command list.                                               |
|                           | `!privs`           | Checks the current privilege level of the agent (User, Admin, or System).|
|                           | `!cmd <command>`   | Executes a command using `cmd.exe`.                                      |
|                           | `!shell <command>` | Executes a command using PowerShell.                                     |
|                           | `!screen`          | Captures a screenshot of the primary display.                            |
|                           | `!exit`            | Removes the agent and deletes all traces from the system.                |
| **Data Exfiltration**     | `!tokengrab`       | Extracts all found Discord tokens.                                       |
|                           | `!browser`         | Extracts passwords, cookies, and other data from web browsers.           |
| **Privilege Escalation**  | `!admin [method]`  | Attempts to bypass UAC. Specify a method or leave blank to try all.      |
|                           | `!system [method]` | Attempts to elevate to `SYSTEM` privileges (requires admin).             |
| **Stealth & Persistence** | `!hide [method]`   | Applies a stealth technique. Methods: `peb`, `hook`, `spoof`, `all`.     |
|                           | `!stealth`         | Reports which stealth features are currently active.                     |
|                           | `!persistence`     | Enables the persistence mechanism for reboot survival.                   |

---

*Have fun.*
