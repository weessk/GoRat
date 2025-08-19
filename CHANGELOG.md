# changelog - latest stuff n hacks

## v0.3.4 - Shell Stability Fix 安定

### fixed

*   annoying ass `context canceled` bug on `!cmd` & `!shell`/`!ps` is finally squashed.
*   commands were basically getting aborted the second they were sent lol.
*   turns out the timeout context was being a little bitch and dying too early. moved it inside the goroutine, so now shell commands actually have time to run.

### changed

*   upped the default command timeout from 30s to 60s, just in case you run some slow-ass shit.

### notes

*   nothing here

---

## v0.3.3 - cockroach drop 

### added

* auto-persist into `%APPDATA%` now lol, more "stealh"
* new startup trick: drops lil `.url` instead of full exe, sneaky af

### changed

* persistence semi recode 
* reg keys & tasks = disguised as basic MS crap
* logic = hella aggressive, keeps reapplying

### notes

* maybe later ill add wmi methods or hijacking, i dont rlly know

---

## v0.3.2 - third drop? idk lol 🔥

### added

* poc for chrome v127+ decryption (app\_bound, super experimental lol)
* now scans all profs, not just "default"
* bookmarks parser, grabs all da bookmarks
* more chromium targets: beta/dev/canary + funky ones like vivaldi

### changed

* full module refactor, faster & cleaner, easier to add future parsers

### notes

* chrome v127+ decryption is mostly a test/poc, may break next builds
* honestly, no clue if this is really the 3rd drop lol, just rollin' with it

