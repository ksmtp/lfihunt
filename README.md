# lfihunt

Find LFI / path traversal on Linux **and** Windows targets, then read files through it.

**OSCP-safe:** detection + reading files you choose. No code-execution wrappers
(`data://`, `expect://`, `php://input`), no log poisoning, no auto-shells. Those
show up as *manual* next steps.

## Install

```bash
pipx install git+https://github.com/ksmtp/lfihunt          # isolated, puts `lfihunt` on PATH
```
or, without installing:
```bash
git clone https://github.com/ksmtp/lfihunt && cd lfihunt
pip install requests
python3 lfihunt.py -u 'http://<IP>/logs?file=app.log'
```

## Usage

```bash
lfihunt -u 'http://<IP>/logs?file=app.log'            # test every param
lfihunt -u 'http://<IP>/logs?file=app.log' --shell    # find, then read files interactively
lfihunt -u 'http://<IP>/' --os windows                # no params -> guess ~45 names
lfihunt -r burp.req                                   # Burp "Copy to file"
```
(run as `python3 lfihunt.py ...` if you cloned instead of installing)

## Injection point (first match wins)

| You give | It tests |
|---|---|
| `FUZZ` in URL, body (`-d`), or a header (`-H 'Cookie: lang=FUZZ'`) | that spot |
| URL ending in `=` | value appended |
| `-p page,file` | those params (added if missing) |
| URL/body with params | each param |
| nothing | ~45 common param names, quick set |

JSON bodies are escaped properly (`-d '{"path":"FUZZ"}'`).

## What it tries

- **Proof files:** `/etc/passwd`, `win.ini`, `hosts`, `system.ini`, `boot.ini`, each checked by content signature.
- **Absolute paths:** `C:\`, `C:/`, `\Windows\` (no drive), lowercase, doubled separators, `file:///`, `::$DATA`, `%00`.
- **Traversal:** depths 1–10 × 15 styles (`../`, `..\`, `....//`, `..././`, `%2e%2e%2f`, `%252e…`, `..%c0%af`, …), leading `/`, `%00`.
- **Path-prefix bypass:** if the param already holds `/var/www/images/x.png`, it also tries `/var/www/images/../../..`. You can set it yourself with `--prefix`.
- **`php://filter`:** base64 reads of the proof files, `index.php` and `index` (results are decoded automatically).
- **Baseline diff:** a match only counts if the signature is *not* in the response for a random missing file, so pages that echo your input don't give false positives.
- **Error leaks:** a `FileNotFoundError` or `failed to open stream` on a missing file gets flagged, because it shows the param reaches a file API.

## Reading files

- `--read PATH` (repeatable) or `--shell` after a find. The reader uses the best working technique: plain absolute paths if they work, otherwise the most reliable traversal.
- `--user NAME` enumerates that user's home/profile for the OS(es) you confirmed: SSH keys, shell/PowerShell history, git/AWS creds, FileZilla configs, `user.txt`. It **lists the links that hit** (the full URL/payload + size), not the file contents — misses are hidden, with a `readable / total` tally. Add `--loot DIR` to save the bodies, or `--read PATH` / `--shell` to dump one. Works on its own (`--user bob` implies a read pass) or with `--shell`.
- **Multiple users:** repeat `--user`, comma-separate (`--user bob,alice`), and/or `--user-file users.txt` (one name per line, `#` comments ok). All are merged and de-duped.
- `--user-wordlist [FILE]` also brutes common filenames inside each user's home, Desktop, Documents, Downloads and `.ssh` (`user.txt`, `id_rsa`, `passwords.xlsx`, `*.kdbx`, `.env`…). With no FILE it uses a built-in list (~38 names); give a FILE for your own. LFI can't list a directory, so this guesses names — it needs a confirmed user, and the path count is users × dirs × names, so mind the request total.

```bash
python3 lfihunt.py -u 'http://<IP>/logs?file=app.log' --os windows --user alice
python3 lfihunt.py -u 'http://<IP>/index.php?page=home' --os linux --user bob,svc --shell
python3 lfihunt.py -u 'http://<IP>/logs?file=app.log' --os windows --user-file users.txt --user-wordlist
```
Get the usernames first from `/etc/passwd` (Linux) or `C:\Users\` guesses / the app itself — lfihunt reads `/etc/passwd` in its proof step, so the names are usually right there.

- It strips the page around the file (diff vs. a baseline) and decodes `php://filter` output.
- Relative paths (`app.py`, `..\web.config`) are sent as typed, so they resolve against the app's folder.
- `--raw` skips finding and sends paths as typed into the `FUZZ` spot.
- `--loot DIR` saves everything you read.
- In the shell, type `hints` for the OS-specific list of files worth reading.

## Options

`-c` cookie · `-H` header · `--proxy http://127.0.0.1:8080` · `-t` threads · `--delay` ·
`--os both|linux|windows` · `-q` quick · `--first` · `-v` every request · `--json FILE` · `--no-color`

A full run costs ~1,100 requests per param (fewer with `--os`, `-q`, or `--first`).
