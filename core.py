"""
Connect to VLESS servers (from subscription links) using sing-box.

sing-box itself uses an "urltest" outbound that periodically tests latency
across servers and automatically connects to the best one - no need to
reimplement that logic manually.

Requirement: the sing-box binary must be installed and available in PATH.
    Termux  : pkg install sing-box
    Windows : winget install sing-box
    macOS   : brew install sing-box
    Linux   : download from releases or use your distro's package manager
    Direct download (all platforms): https://github.com/SagerNet/sing-box/releases

Run (same command on Termux too):
    python3 vless_connect.py

After starting, a mixed SOCKS5 + HTTP proxy comes up on:
    127.0.0.1:10808
Use that same address/port for both SOCKS5 and HTTP in your app/browser.
"""

import atexit
import base64
import concurrent.futures
import contextlib
import gzip
import heapq
import json
import os
import queue
import random
import re
import shutil
import shlex
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import zlib
import html as html_lib
import io

# Protocol parsers are isolated in parser.py so the launcher can keep the
# startup path small and the parsing layer can be maintained independently.
from source_memory import SourceMemory
from parser import (
    parse_vless_uri, parse_trojan_uri, parse_hysteria2_uri, parse_hysteria_uri,
    parse_wireguard_uri, parse_vmess_uri, parse_ss_uri, parse_tuic_uri,
    parse_shadowtls_uri, parse_anytls_uri, parse_naive_uri, parse_ssh_uri,
    parse_socks_uri, parse_http_proxy_uri, parse_proxy_uri, parse_snell_uri,
    apply_endpoints, wireguard_to_endpoint,
)

# ---------------------------------------------------------------------------
# Terminal styling: colored status symbols + an animated spinner for
# steps that take a moment (network calls, latency tests, etc.)
#
# Everything below is careful to only ever occupy ONE terminal row. Mobile
# terminals (Termux etc.) are often only ~35-45 columns wide - if a status
# line is longer than that, the terminal auto-wraps it onto a second row.
# "\r" then only returns the cursor to the start of THAT row, not the start
# of the logical line, so every redraw prints a brand new pair of rows
# instead of overwriting the old ones - that's what causes hundreds of
# duplicate "Stage 3/3..." lines to pile up on narrow screens. The fix is
# to always measure the real terminal width and truncate to it, so a wrap
# can never happen in the first place.
# ---------------------------------------------------------------------------
class _C:
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    GREEN = "\x1b[92m"
    RED = "\x1b[91m"
    ORANGE = "\x1b[38;5;208m"
    YELLOW = "\x1b[93m"  # active/status highlight color
    CYAN = "\x1b[96m"
    MAGENTA = "\x1b[95m"
    BLUE = "\x1b[94m"
    CRIMSON = "\x1b[38;2;243;42;86m"  # inactive-command color

OK = f"{_C.GREEN}✓{_C.RESET}"
WARN = f"{_C.YELLOW}⚠{_C.RESET}"
FAIL = f"{_C.RED}✗{_C.RESET}"
INFO = f"{_C.CYAN}ℹ{_C.RESET}"

CLEAR_LINE = "\x1b[2K\r"  # erase the whole current row, then return to column 0


def term_width() -> int:
    try:
        return shutil.get_terminal_size(fallback=(80, 24)).columns
    except Exception:
        return 80


def _visible_len(s: str) -> int:
    """Length of a string as it appears on screen, ignoring ANSI color
    codes (which have zero visible width but count towards len())."""
    out, in_esc = 0, False
    for ch in s:
        if ch == "\x1b":
            in_esc = True
        elif in_esc:
            if ch.isalpha():
                in_esc = False
        else:
            out += 1
    return out


def _visible_width_wide(s: str) -> int:
    """Like _visible_len, but counts emoji (which render as 2 terminal
    columns almost everywhere, including Termux) as width 2 instead of 1.
    Used only for the command-help section headers, which mix emoji with
    plain text and must still line up with the columns below them."""
    out, in_esc = 0, False
    for ch in s:
        if ch == "\x1b":
            in_esc = True
        elif in_esc:
            if ch.isalpha():
                in_esc = False
        else:
            out += 2 if ord(ch) >= 0x2600 else 1
    return out


def _pad_visible_wide(s: str, width: int) -> str:
    """Right-pads s with spaces so its ON-SCREEN width (see
    _visible_width_wide) reaches `width`, ignoring ANSI color codes."""
    pad = width - _visible_width_wide(s)
    return s + (" " * pad if pad > 0 else "")


def _fit_to_width(s: str, width: int) -> str:
    """Truncates plain (non-ANSI) text to fit within `width` columns."""
    if len(s) <= width:
        return s
    if width <= 1:
        return s[:max(width, 0)]
    return s[: width - 1] + "…"


def clear_line():
    """Erases whatever is on the current terminal row."""
    sys.stdout.write(CLEAR_LINE)
    sys.stdout.flush()


def print_transient(text: str):
    """Shows a short-lived status line that the NEXT print_transient(),
    Spinner, ProgressBar, or ordinary print() call will erase/replace.
    Used for routine startup steps so the screen only ever shows 'what's
    happening right now' instead of piling up permanent scrollback.
    Truncated to the terminal width so it can never wrap."""
    text = _fit_to_width(text, max(term_width() - 1, 1))
    sys.stdout.write(CLEAR_LINE + text)
    sys.stdout.flush()


class Spinner:
    """Animated spinner for a blocking step that doesn't print anything of
    its own while it runs.

        with Spinner("Fetching subscriptions..."):
            do_the_slow_thing()

    On success the line is simply cleared (transient - the next thing
    printed takes its place, so the screen doesn't fill up with a
    permanent history of every startup step). On failure (an exception, or
    `sp.failed = True` set from inside the `with` block) a red ✗ line is
    left in place instead, since problems should stay visible.

    Only use this around code that stays silent while running - if the
    wrapped block also calls print(), its output will get interleaved with
    the spinner's redraws and look garbled.
    """
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, message: str, stream=None):
        self.message = message
        self.failed = False
        # `stream`: write to this stream instead of whatever sys.stdout is at
        # the moment. Auto Setting uses it to keep a visible spinner on the real
        # terminal while everything the work itself prints is silenced.
        self._stream = stream
        self._stop = threading.Event()
        self._thread = None

    def _out(self):
        return self._stream if self._stream is not None else sys.stdout

    def _line(self, frame: str) -> str:
        width = max(term_width() - 1, 1)
        prefix_len = _visible_len(frame) + 1  # frame + one space
        return f"{frame} {_fit_to_width(self.message, max(width - prefix_len, 1))}"

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            frame = f"{_C.CYAN}{self.FRAMES[i % len(self.FRAMES)]}{_C.RESET}"
            out = self._out()
            out.write(CLEAR_LINE + self._line(frame))
            out.flush()
            i += 1
            time.sleep(0.08)

    def __enter__(self):
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        out = self._out()
        if exc_type is not None or self.failed:
            out.write(CLEAR_LINE + self._line(FAIL) + "\n")
        else:
            out.write(CLEAR_LINE)  # transient: leave nothing behind
        out.flush()
        return False  # never swallow exceptions


class ProgressBar:
    """Animated single-line percentage bar for a step made of many small
    units of work running concurrently (e.g. testing N servers at once).

        with ProgressBar("Stage 1/3", total=len(outbounds)) as pb:
            with concurrent.futures.ThreadPoolExecutor(...) as executor:
                for future in concurrent.futures.as_completed(futures):
                    ...
                    pb.tick()  # call once per completed unit of work

    Always fits on one terminal row (bar width shrinks on narrow screens,
    and is dropped entirely if there's no room), and clears itself on
    success like Spinner - only a failed run leaves a line behind.

    Thread-safe: tick() can be called from any worker thread.
    """
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    MAX_BAR_WIDTH = 24
    MIN_BAR_WIDTH = 6

    def __init__(self, message: str, total: int):
        self.message = message
        self.total = max(total, 1)  # avoid div-by-zero; a 0-total bar just sits at 100%
        self.done = 0
        self.failed = False
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def tick(self, n: int = 1):
        """Call once per completed unit of work (thread-safe)."""
        with self._lock:
            self.done = min(self.done + n, self.total)

    def _line(self, frame: str) -> str:
        with self._lock:
            done, total = self.done, self.total
        pct = int(done * 100 / total)
        pct_txt = f"{pct:3d}%"
        width = max(term_width() - 1, 1)
        prefix_len = _visible_len(frame) + 1  # frame + one space
        msg = _fit_to_width(self.message, max(width // 2, 1))
        # everything except the bar itself: "<frame> <msg> [] <pct>"
        fixed_len = prefix_len + len(msg) + 1 + 2 + 1 + len(pct_txt)
        bar_width = width - fixed_len
        if bar_width < self.MIN_BAR_WIDTH:
            # not enough room for a bar - just show the message and percent
            return f"{frame} {msg} {pct_txt}"
        bar_width = min(bar_width, self.MAX_BAR_WIDTH)
        filled = int(bar_width * done / total)
        bar = "█" * filled + "░" * (bar_width - filled)
        return f"{frame} {msg} [{_C.CYAN}{bar}{_C.RESET}] {pct_txt}"

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            frame = f"{_C.CYAN}{self.FRAMES[i % len(self.FRAMES)]}{_C.RESET}"
            sys.stdout.write(CLEAR_LINE + self._line(frame))
            sys.stdout.flush()
            i += 1
            time.sleep(0.08)

    def __enter__(self):
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        if exc_type is not None or self.failed:
            sys.stdout.write(CLEAR_LINE + self._line(FAIL) + "\n")
        else:
            sys.stdout.write(CLEAR_LINE)  # transient: leave nothing behind
        sys.stdout.flush()
        return False  # never swallow exceptions


class StepCounter:
    """Gives every stage of the connection pipeline a consistent
    'Name i/N' label (e.g. 'TCP 4/10', 'DNS 10/10') instead of a generic
    'Stage X/Y' - so each status line says what's actually happening.

        steps = StepCounter(["Ports", "Fetch", "Find", "TCP", "TLS",
                              "Verify", "Geo", "Connect", "Bypass", "DNS"])
        print_transient(f"{INFO} {steps.next()}")   # "Ports 1/10"
        ...
        print_transient(f"{INFO} {steps.next()}")   # "Fetch 2/10"
    """

    def __init__(self, names: list):
        self.names = names
        self.total = len(names)
        self.i = 0

    def next(self) -> str:
        self.i += 1
        name = self.names[self.i - 1] if self.i <= self.total else self.names[-1]
        return f"{name} {self.i}/{self.total}"


REQUIRED_SINGBOX_VERSION = (1, 14, 0)  # this build targets sing-box 1.14.x (tested design: 1.14.1).
# 1.14 needs: WireGuard as an *endpoint* (1.13+ only), Snell, Hysteria2 gecko/
# BBR profile/Chrome-parrot, optimistic DNS cache and the new UDP NAT fields.
FRAGMENT_MIN_VERSION = (1, 13, 0)  # first sing-box release with the
# route-options tls_fragment/tls_record_fragment rule action this needs

FRAGMENT_PRESETS = {
    # Each varies how aggressively the TLS ClientHello (and optionally the
    # whole TLS record stream) gets split into extra TCP segments, to make
    # it harder for simple DPI to read the SNI and throttle/reset the
    # connection. There's no single "best" setting - it depends on what
    # the local ISP's DPI actually looks for, so these are meant to be
    # tried live (F1..F4) rather than picked once and forgotten.
    # NOTE: tls_fragment and tls_record_fragment are NOT combined in any
    # preset below. sing-box 1.13.x rejects a route-options rule that sets
    # both to true at once (config validation error on startup) - this is
    # what previously made F2/F3 fail here, since they used to enable both
    # simultaneously. Each preset now toggles exactly one of the two.
    1: {"name": "Light",       "short": "L", "tls_fragment": True,  "tls_record_fragment": False, "tls_fragment_fallback_delay": "10ms"},
    2: {"name": "Balanced",    "short": "B", "tls_fragment": True,  "tls_record_fragment": False, "tls_fragment_fallback_delay": "30ms"},
    3: {"name": "Aggressive",  "short": "A", "tls_fragment": True,  "tls_record_fragment": False, "tls_fragment_fallback_delay": "60ms"},
    4: {"name": "Record-only", "short": "R", "tls_fragment": False, "tls_record_fragment": True,  "tls_fragment_fallback_delay": "20ms"},
}
FRAGMENT_PRESET_COMMANDS = {f"f{i}": i for i in FRAGMENT_PRESETS}  # "f1".."f4"
FRAGMENT_TOGGLE_COMMANDS = {"f", "fragment"}  # re-applies/turns off whichever preset was last active


def fragment_route_rule(preset_id: int) -> dict:
    """The sing-box route-options rule for one FRAGMENT_PRESETS entry.

    Shared by the live config (build_singbox_config) and by Auto Setting's
    isolated fragment tests, so what gets measured is exactly what gets applied."""
    preset = FRAGMENT_PRESETS[preset_id]
    return {
        "action": "route-options",
        "tls_fragment": preset["tls_fragment"],
        "tls_record_fragment": preset["tls_record_fragment"],
        "tls_fragment_fallback_delay": preset["tls_fragment_fallback_delay"],
    }

# Built-in subscriptions (old S1-S8) were removed. SUB_URLS/SUB_NAMES now only hold
# links the user adds live with 'SL' (they show up as L1, L2, ...).
SUB_URLS = []
SUB_NAMES = []

BUILTIN_SUB_COUNT = 0  # everything from S{BUILTIN_SUB_COUNT+1} onward is a
# link the user added live via the 'SL' (SubLink) command, not one shipped with the
# script - see load_custom_sublinks()/save_custom_sublinks() and the SL/DL command
# handlers further down. Kept so DL only ever lets the user delete THOSE, never S1-S8.

# Every *.json file the program creates for its own use (caches, saved settings, the live
# sing-box config...) lives in this one subfolder next to the script, so the program's
# folder stays readable instead of filling up with loose .json files at the top level.
JSON_DATA_DIR = os.path.abspath("Jason")
try:
    os.makedirs(JSON_DATA_DIR, exist_ok=True)
except OSError:
    pass


def _json_path(name: str) -> str:
    """Absolute path of one of the program's own *.json files, inside JSON_DATA_DIR."""
    return os.path.join(JSON_DATA_DIR, name)


CUSTOM_SUBLINKS_PATH = _json_path("custom_sublinks.json")  # links added via 'SL',
# persisted so they're still there (as Link 1, Link 2...) after a restart.


def load_custom_sublinks() -> list:
    try:
        with open(CUSTOM_SUBLINKS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [u for u in data if isinstance(u, str) and u.strip()]
    except Exception:
        return []


def save_custom_sublinks(urls: list):
    try:
        with open(CUSTOM_SUBLINKS_PATH, "w", encoding="utf-8") as f:
            json.dump(urls, f)
    except Exception:
        pass


for _custom_sublink_url in load_custom_sublinks():
    SUB_URLS.append(_custom_sublink_url)
    SUB_NAMES.append(f"Link {len(SUB_URLS) - BUILTIN_SUB_COUNT}")

CONFIG_PATH = _json_path("singbox-config.json")
GEOSITE_IR_URL = "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs"
GEOIP_IR_URL = "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs"
GEOSITE_IR_PATH = os.path.abspath("geosite-ir.srs")
GEOIP_IR_PATH = os.path.abspath("geoip-ir.srs")
VLESS_CACHE_PATH = _json_path("vless_cache.json")  # last successfully fetched vless:// lines per subscription
FREE_VLESS_CACHE_PATH = _json_path("free_vless_cache.json")  # last working free links (FV mode)
SWITCH_SERVER_CACHE_PATH = _json_path("switch_server_cache.json")  # best verified server pools per FV/S1-S8/custom source
FAST_CONNECT_PATH = _json_path("fast_connect.json")  # last successfully connected outbound for optional fast startup
FREE_VLESS_COUNT = 10  # keep the 10 fastest verified servers when available
FREE_VLESS_MIN_WORKING = 6  # desired minimum before a source is accepted (classic, non-quality mode)

# ---- Free Vless QUALITY GATE ------------------------------------------------
# A config that answers ONE quick request is not necessarily a good config: many
# public nodes pass that first probe and then stall, get throttled, or drop when
# several connections are used at once. With FV_QUALITY_MODE on, every candidate
# that passes the quick probe must ALSO survive a stability test and a small
# download test (in the same temporary sing-box process) before it is kept.
# Scanning STOPS as soon as FV_QUALITY_TARGET good nodes are found (default: the
# FIRST one) and FV connects right away; candidates already being tested at that
# moment are allowed to finish, so you sometimes get a few extra nodes for free.
# The silent background search (FV_RESERVE_*) then finds more.
# Set FV_QUALITY_MODE = False to return to the old fast/loose behaviour.
FV_QUALITY_MODE = True
FV_QUALITY_TARGET = 1            # stop scanning and connect as soon as this many GOOD nodes are found
FV_QUALITY_FALLBACK_MIN = 2      # if a source runs out of time/configs, accept it with at least this many
FV_SOURCE_TIME_BUDGET = 150.0    # seconds to spend on one source before moving to the next one
FV_QUALITY_RELAX_AFTER = 5       # if the first N sources give nothing, drop the download test for the rest
FV_QUALITY_ROUNDS = 3            # stability rounds (each round = FV_QUALITY_PARALLEL simultaneous requests)
FV_QUALITY_PARALLEL = 3          # simultaneous HTTPS requests per round (catches nodes that die under load)
FV_QUALITY_ROUND_GAP = 1.2       # seconds between rounds (catches nodes that die a moment after connecting)
FV_QUALITY_REQ_TIMEOUT = 5.0     # seconds allowed for one probe request
FV_QUALITY_MAX_FAILS = 1         # failed probes tolerated (of 1 + ROUNDS*PARALLEL) before a node is rejected
FV_QUALITY_MAX_MEDIAN_MS = 2500  # reject if the median probe latency is above this
FV_QUALITY_MAX_WORST_MS = 4500   # reject if the slowest successful probe is above this
FV_QUALITY_DL_BYTES = 400_000    # size of the throughput test download
FV_QUALITY_DL_MIN_KBPS = 80      # minimum acceptable download speed in KB/s
FV_QUALITY_DL_TIMEOUT = 12.0     # the whole download must finish within this many seconds
FV_QUALITY_DL_CONCURRENCY = 2    # download tests running at once (so they don't steal each other's bandwidth)
FV_QUALITY_PROBE_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://www.google.com/generate_204",
]
FV_QUALITY_DL_URLS = [
    "https://speed.cloudflare.com/__down?bytes=400000",
    "https://cachefly.cachefly.net/1mb.test",
    "https://fsn1-speed.hetzner.com/100MB.bin",
]

# ---- Free Vless RESERVE (silent background search + automatic failover) ------
# After you are connected, a silent background thread looks for extra healthy
# configs (from the same source first) until FV_RESERVE_TARGET are stored in
# fv_reserve.json, then stops.
# Testing always happens on the phone's normal internet (the temporary test
# sing-box processes dial the servers directly), so the VPN is not involved.
# The stored nodes are appended to the Switch Server numbers while in FV mode,
# and are used automatically if the connection dies (or when you type FV).
# Set FV_RESERVE_MODE = False to disable all of it.
FV_RESERVE_MODE = True
FV_RESERVE_PATH = _json_path("fv_reserve.json")
# Pool size shown in "Switch Server": the server you are connected to + the ones found
# silently in the background. The background search aims for FV_POOL_TARGET_TOTAL servers
# (Switch Server : 1 - 10) and is happy with FV_POOL_MIN_TOTAL (Switch Server : 1 - 6)
# once FV_RESERVE_SOFT_BUDGET seconds have passed.
FV_POOL_TARGET_TOTAL = 10
FV_POOL_MIN_TOTAL = 6
FV_RESERVE_SOFT_BUDGET = 150.0    # after this many seconds a pool of FV_POOL_MIN_TOTAL is accepted
FV_PROTOCOL_SAME_BUDGET = 180.0   # protocol search: seconds spent looking for MORE servers of the SAME
                                  # protocol before other protocols are used to reach FV_POOL_MIN_TOTAL
FV_RESERVE_PROTO_PER_FEED = 60    # protocol-bound background search: candidates examined per feed
FV_RESERVE_SATISFIED_RETRY = 3600.0  # pool already >= FV_POOL_MIN_TOTAL: wait this long before topping it up
FV_RESERVE_TARGET = FV_POOL_TARGET_TOTAL - 1   # hard cap of EXTRA servers stored next to the connected one
FV_RESERVE_WORKERS = 2            # tests running at once in the background (kept low on purpose)
FV_RESERVE_BATCH = 16             # candidates handed to the workers at a time
FV_RESERVE_BATCH_PAUSE = 1.0      # seconds of rest between batches (battery / heat / bandwidth)
FV_RESERVE_SOURCE_BUDGET = 240.0  # seconds spent on one source before moving to the next
FV_RESERVE_MAX_CANDIDATES = 600   # random candidates examined per source
FV_RESERVE_RETRY_AFTER = 600.0    # if all sources were tried without reaching the target, wait this long
FV_RESERVE_NOTIFY = True          # one Android notification when the reserve becomes full
FV_RESERVE_FAILOVER_STOP = 1      # on failover / FV, connect as soon as this many stored nodes pass a quick test
FV_RESERVE_FAILOVER_DEADLINE = 25.0
# Connection watchdog (Free Vless mode only): a real request through the local
# proxy every FV_HEALTH_INTERVAL seconds; FV_HEALTH_MAX_FAILS failures in a row
# while the phone itself still has internet = the server is dead -> failover.
FV_HEALTH_ENABLED = True
FV_HEALTH_INTERVAL = 10.0
FV_HEALTH_GRACE = 20.0            # seconds after a (re)connect before checking
FV_HEALTH_MAX_FAILS = 3
FV_HEALTH_TIMEOUT = 8.0

# ---- Type Country: find a Free Vless server whose exit IP is in a chosen country ----
FV_COUNTRY_TIME_BUDGET = 360.0   # seconds spent searching before giving up (the current connection is kept)
FV_COUNTRY_WORKERS = 6           # candidates tested at once
FV_COUNTRY_TIER1_MAX = 60        # per source: configs whose name mentions the country (tested first)
FV_COUNTRY_BLIND_MAX = 24        # per source: random other configs (their real exit country is checked too)
FV_COUNTRY_QUALITY_LEVEL = 1     # extra stability test on a country match (0 = none, 1 = stability, 2 = + download)
FV_PROTOCOL_TIME_BUDGET = 360.0  # seconds spent searching for a requested protocol
FV_PROTOCOL_WORKERS = 6
FV_PROTOCOL_MAX_PER_SOURCE = 80  # cap per source so a huge feed cannot monopolize the search
FV_PROTOCOL_SOURCE_BUDGET = 40.0 # seconds one source may use before the next-best source is tried
SOURCE_MEMORY_PATH = _json_path("source_memory.json")  # which source delivered results before
_SOURCE_MEMORY = SourceMemory(SOURCE_MEMORY_PATH)

# ---- Type Ping: search Free Vless/public sources by measured end-to-end latency ----
# P318 means "1..350 ms" and P400 means "1..450 ms". The upper limit is the
# next 50-ms bucket above the number entered, which matches the phone-friendly
# examples above and avoids treating a bare number as a server-switch command.
FV_PING_TIME_BUDGET = 240.0
FV_PING_WORKERS = 8
FV_PING_MAX_PER_SOURCE = 80
FV_PING_TARGET = FREE_VLESS_COUNT

# Protocol names accepted in the Type Protocol, Country and Commands prompt.
# Values are the sing-box outbound type produced by parser.py.
_PROTOCOL_ALIASES = {
    "vless": "vless",
    "vmess": "vmess",
    "trojan": "trojan",
    "shadowsocks": "shadowsocks", "shadow socks": "shadowsocks", "ss": "shadowsocks",
    "hysteria": "hysteria",
    "hysteria2": "hysteria2", "hysteria 2": "hysteria2", "hy2": "hysteria2",
    "tuic": "tuic",
    "wireguard": "wireguard", "wg": "wireguard", "warp": "wireguard",
    "shadowtls": "shadowtls", "shadow tls": "shadowtls",
    "anytls": "anytls", "any tls": "anytls",
    "naive": "naive", "naiveproxy": "naive", "naive proxy": "naive",
    "ssh": "ssh",
    "snell": "snell",
    "socks": "socks", "socks5": "socks", "socks4": "socks",
    "http": "http", "https": "http", "http proxy": "http", "https proxy": "http",
}
_PROTOCOL_CANONICAL = {
    "vless": "VLESS", "vmess": "VMess", "trojan": "Trojan",
    "shadowsocks": "Shadowsocks", "hysteria": "Hysteria", "hysteria2": "Hysteria2",
    "tuic": "TUIC", "wireguard": "WireGuard", "shadowtls": "ShadowTLS",
    "anytls": "AnyTLS", "naive": "NaiveProxy", "ssh": "SSH", "snell": "Snell",
    "socks": "SOCKS", "http": "HTTP Proxy",
}
_PROTOCOL_INDEX = None

def _norm_protocol_text(text: str) -> str:
    t = str(text or "").strip().lower().replace("_", " ").replace("-", " ")
    return re.sub(r"\s+", " ", t).strip()

def _protocol_index() -> dict:
    global _PROTOCOL_INDEX
    if _PROTOCOL_INDEX is None:
        idx = {}
        for alias, target in _PROTOCOL_ALIASES.items():
            idx[_norm_protocol_text(alias)] = target
        for target, name in _PROTOCOL_CANONICAL.items():
            idx[_norm_protocol_text(name)] = target
        _PROTOCOL_INDEX = idx
    return _PROTOCOL_INDEX

def resolve_protocol(text: str):
    """Return (sing-box type, canonical display name) for an exact/prefix/near protocol name."""
    t = _norm_protocol_text(text)
    if not t or len(t) > 30:
        return None
    idx = _protocol_index()
    target = idx.get(t)
    if target is None:
        # Prefix completion: Finite, deterministic and only accepts an unambiguous match.
        matches = sorted({v for k, v in idx.items() if k.startswith(t)})
        if len(matches) == 1:
            target = matches[0]
    if target is None and len(t) >= 4:
        import difflib
        near = difflib.get_close_matches(t, list(idx.keys()), n=1, cutoff=0.78)
        if near:
            target = idx[near[0]]
    if target is None:
        return None
    return target, _PROTOCOL_CANONICAL.get(target, target.upper())

def _protocol_match(ob: dict, wanted: str) -> bool:
    if not isinstance(ob, dict):
        return False
    typ = str(ob.get("type", "")).lower()
    if typ == wanted:
        return True
    # WARP is represented by sing-box as WireGuard.
    return wanted == "wireguard" and typ == "wireguard"


# IMPORTANT: Free Vless is a completely separate pool from S1-S8. Pressing FV
# starts at T1 (whatever source is first below) every time, then walks Barry-Far
# Sub2..Sub5, and ONLY after
# those five fail does it enter the curated fallback sources below.
# S1-S8 are never consulted by the FV failover chain.
FREE_VLESS_SOURCES = [
    # Primary FV sources: exact order is intentional.
    "https://sub.vlessfo.ru/vlessforu/working_configs.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub3.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub4.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub5.txt",

    # Fallbacks: curated/smaller feeds are preferred over giant 7k/16k/39k
    # dumps. The first fallback is 0xRadikal Verified, as requested.
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_013.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_014.txt",
    "https://raw.githubusercontent.com/coldwater-10/V2ray-Config/main/Sub7.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_015.txt",
    "https://raw.githubusercontent.com/coldwater-10/V2ray-Config/main/Sub10.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/refs/heads/main/config/tcp-pass/batch_001.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/sub1.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/sub2.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub1.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub2.txt",

    # New fallbacks (added on top of the original 20): two more GitHub
    # aggregators not previously in this list, plus two live public
    # Telegram channels. Telegram entries use the t.me/s/<channel> web
    # preview - see fetch_telegram_channel_configs() - which needs no
    # login/API key; fetch_subscription() detects the t.me/s/ URL and
    # routes it there automatically, so nothing else has to special-case
    # these two.
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://t.me/s/azadNETproxy",
    "https://t.me/s/proxyvv2",

    # Telegram-collected feeds (TGParse by Surfboardv2ray: parses configs out of many public
    # Telegram channels every few minutes and splits them by protocol; base64 files - the
    # downloader decodes them). "mixed" carries EVERY protocol (hysteria2, hysteria, tuic,
    # trojan, ss, socks...), "vless" the Vless/Reality ones. They are T25 and T26.
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vless",

    # User-requested additions (T27-T29): three more public Telegram channels.
    "https://t.me/s/Argo_VPN1",
    "https://t.me/s/free_proxy_db",
    "https://t.me/s/vpnjey",
]

FREE_VLESS_SOURCE_NAMES = [
    "VlessForU Working", "Barry-Far Sub1", "Barry-Far Sub2", "Barry-Far Sub3", "Barry-Far Sub4", "Barry-Far Sub5",
    "0xRadikal Verified",
    "Delta-Kronecker #013", "Delta-Kronecker #014", "coldwater-10 Sub7",
    "Delta-Kronecker #015", "coldwater-10 Sub10",
    "Delta-Kronecker #001", "MatinGhanbari Super", "MatinGhanbari Sub1",
    "MatinGhanbari Sub2", "Epodonios Sub1", "Epodonios Sub2",
    "mahdibland Eternity", "roosterkid Raw", "TG azadNETproxy", "TG proxyvv2",
    "TGParse Mixed (Telegram)", "TGParse Vless (Telegram)",
    "Telegram@Argo_VPN1", "Telegram@free_proxy_db", "Telegram@vpnjey",
]
FREE_VLESS_SOURCE_CODES = [
    *(f"S{i}" for i in range(1, 6)),
    *(f"F{i}" for i in range(1, len(FREE_VLESS_SOURCES) - 4)),
    # S1-S5 (5 codes) + F1..F(N-5) (N-5 codes) = N codes total, one per source,
    # for ANY N - every source, including T27-T29, gets a real code, so
    # connect_source_label() below can always map a connected tag back to its
    # T<n>. (An earlier "- 7" here undercounted and left T27-T29 with no code
    # at all, silently breaking their "CONNECT to T<n>" label.)
]

# Extra protocol-specific feeds used ONLY by protocol search. These do not
# change the user's T1-T20 source numbering. They exist because some public
# repositories publish rare protocols in dedicated files while their general
# bundles contain few or none of them. All candidates still pass our own
# sing-box end-to-end verification before a connection is accepted.
PROTOCOL_EXTRA_SOURCE_URLS = {
    "hysteria": [
        ("https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/hy.txt", "GFP Hysteria"),
        ("https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hysteria", "TGParse Hysteria"),
        ("https://raw.githubusercontent.com/liMilCo/v2r/main/pro/hysteria.txt", "liMilCo Hysteria"),
    ],
    "hysteria2": [
        ("https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/hy2.txt", "GFP Hysteria2"),
        ("https://raw.githubusercontent.com/PrinceVSFX/Hysteria2-Configs/main/Configs_list.txt", "PrinceVSFX Hysteria2"),
        ("https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hysteria2", "TGParse Hysteria2"),
        ("https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hy2", "TGParse HY2"),
        ("https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Hysteria2.txt", "Argh94 Hysteria2"),
        ("https://raw.githubusercontent.com/giromo/Collector/refs/heads/main/Splitted-By-Protocol/Hysteria2.txt", "Giromo Hysteria2"),
        ("https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/hysteria2.txt", "0xRadikal Hysteria2"),
        ("https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/hysteria2.txt", "Morpheus Hysteria2"),
        ("https://t.me/s/vpnjey", "TG vpnjey Hysteria2"),
    ],
    "tuic": [
        ("https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/tuic.txt", "GFP TUIC"),
        ("https://raw.githubusercontent.com/Kolandone/v2raycollector/main/tuic.txt", "Kolandone TUIC"),
        ("https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Tuic.txt", "Argh94 TUIC"),
        ("https://raw.githubusercontent.com/giromo/Collector/refs/heads/main/Splitted-By-Protocol/Tuic.txt", "Giromo TUIC"),
        ("https://raw.githubusercontent.com/coldwater-10/V2ray-Config-Lite/main/Splitted-By-Protocol/tuic.txt", "Coldwater Lite TUIC"),
        ("https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/tuic.txt", "0xRadikal TUIC"),
        ("https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/tuic.txt", "Morpheus TUIC"),
    ],
    "wireguard": [
        ("https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/wireguard.txt", "GFP WireGuard"),
        ("https://raw.githubusercontent.com/Delta-Kronecker/WARP-Config/main/ALL.txt", "Delta-Kronecker WARP"),
        ("https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/WireGuard.txt", "Argh94 WireGuard"),
        ("https://raw.githubusercontent.com/giromo/Collector/refs/heads/main/Splitted-By-Protocol/WireGuard.txt", "Giromo WireGuard"),
        ("https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/wireguard.txt", "Morpheus WireGuard"),
    ],
    "anytls": [
        ("https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/anytls.txt", "GFP AnyTLS"),
        ("https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/anytls.txt", "0xRadikal AnyTLS"),
        ("https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed", "TGParse Mixed"),
    ],
    "naive": [
        ("https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed", "TGParse Mixed"),
    ],
    "shadowtls": [
        ("https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed", "TGParse Mixed"),
    ],
    "socks": [
        ("https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/socks.txt", "GFP SOCKS"),
        ("https://raw.githubusercontent.com/Kolandone/v2raycollector/main/socks.txt", "Kolandone SOCKS"),
    ],
    "http": [
        ("https://raw.githubusercontent.com/wiki/gfpcom/free-proxy-list/lists/http.txt", "GFP HTTP"),
    ],
    # A broad mixed feed from a maintained collector; useful as an extra pass
    # for protocols that are not published in their own dedicated file.
    "vless": [
        ("https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vless", "TGParse VLESS"),
        ("https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vless.txt", "0xRadikal VLESS"),
    ],
    "vmess": [
        ("https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/vmess", "TGParse VMess"),
        ("https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vmess.txt", "0xRadikal VMess"),
    ],
    "trojan": [
        ("https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/trojan", "TGParse Trojan"),
        ("https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/trojan.txt", "0xRadikal Trojan"),
    ],
    "shadowsocks": [
        ("https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/ss", "TGParse Shadowsocks"),
        ("https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/shadowsocks.txt", "0xRadikal Shadowsocks"),
    ],
}

# ---------------------------------------------------------------------------
# Live Cloudflare WARP identity generation (used only for the "wireguard"/
# "warp" protocol search).
#
# WARP isn't a proxy that can be published/shared the way a vless:// or
# trojan:// link is: every real WARP peer is tied to ONE registered device
# key. A WARP config posted in a repo or a Telegram channel is someone
# else's private key - it may already be dead, and if it still works it's
# shared by everyone who copied that same post. That's why the community's
# public WireGuard/WARP lists are thin and often stale (this is the actual
# cause when a WireGuard/WARP search comes back with 0 verified servers -
# nothing is broken in the search code itself, the shared config sources
# for this one protocol are just an inherently weak source of truth).
#
# The standard fix (used by well-known open tools such as wgcf, warp.sh and
# warp-reg) is to register a brand-new, free, anonymous WARP identity on
# demand using Cloudflare's own client registration endpoint - the same one
# the official 1.1.1.1 app uses. This always yields a working peer instead
# of hoping a shared one is still alive. No login/account/API key needed;
# it's an open registration endpoint by design (anyone can create a free
# WARP identity, same as installing the official app and tapping "connect").
WARP_PEER_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="  # Cloudflare's
# well-known WARP edge public key - constant for every free identity.
WARP_FALLBACK_ENDPOINT = "engage.cloudflareclient.com:2408"
WARP_REG_API_VERSIONS = ("v0a745", "v0a936", "v0a944", "v0a983")  # Cloudflare bumps
# this version segment occasionally; trying a short list keeps registration
# working without needing an update every time it changes upstream.


def _warp_wg_keypair(binary: str):
    """Generate a fresh Curve25519 keypair using the sing-box binary the rest
    of the program already requires (`sing-box generate wg-keypair`), so no
    extra crypto dependency is needed. Returns (private_key, public_key) as
    base64 strings, or (None, None) on failure."""
    try:
        result = subprocess.run(
            [binary, "generate", "wg-keypair"],
            capture_output=True, text=True, timeout=10,
        )
        out = (result.stdout or "") + "\n" + (result.stderr or "")
        priv = re.search(r"PrivateKey\s*[:=]\s*([A-Za-z0-9+/=]{40,})", out, re.IGNORECASE)
        pub = re.search(r"PublicKey\s*[:=]\s*([A-Za-z0-9+/=]{40,})", out, re.IGNORECASE)
        if priv and pub:
            return priv.group(1).strip(), pub.group(1).strip()
    except Exception:
        pass
    return None, None


def _random_id_string(length: int) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(random.choice(alphabet) for _ in range(length))


def generate_warp_wireguard_config(binary: str) -> dict:
    """Register one brand-new free Cloudflare WARP identity and return a dict
    describing a ready-to-use WireGuard peer, or None on any failure (network
    down, Cloudflare endpoint version changed, etc. - callers should treat
    that exactly like any other source coming back empty)."""
    private_key, public_key = _warp_wg_keypair(binary)
    if not private_key or not public_key:
        return None

    install_id = _random_id_string(22)
    body = json.dumps({
        "key": public_key,
        "install_id": install_id,
        "fcm_token": f"{install_id}:APA91b{_random_id_string(134)}",
        "warp_enabled": False,
        "tos": time.strftime("%Y-%m-%dT%H:%M:%S") + ".000+00:00",
        "type": "Android",
        "locale": "en_US",
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "User-Agent": "okhttp/3.12.1",
    }

    for version in WARP_REG_API_VERSIONS:
        try:
            req = urllib.request.Request(
                f"https://api.cloudflareclient.com/{version}/reg",
                data=body, headers=headers, method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
        except Exception:
            continue

        try:
            cfg = data["config"]
            peer = cfg["peers"][0]
            endpoint_host = peer.get("endpoint", {}).get("host") or WARP_FALLBACK_ENDPOINT
            addr_v4 = cfg["interface"]["addresses"].get("v4")
            addr_v6 = cfg["interface"]["addresses"].get("v6")
            client_id_b64 = cfg.get("client_id", "")
            reserved = list(base64.b64decode(client_id_b64 + "=" * (-len(client_id_b64) % 4)))[:3]
            if not addr_v4 or not endpoint_host:
                continue
            return {
                "private_key": private_key,
                "public_key": peer.get("public_key") or WARP_PEER_PUBLIC_KEY,
                "endpoint": endpoint_host,
                "address_v4": addr_v4,
                "address_v6": addr_v6,
                "reserved": reserved or [0, 0, 0],
            }
        except Exception:
            continue
    return None


def _warp_identity_to_uri(identity: dict, remark: str = "Cloudflare WARP (auto)") -> str:
    """Build a wireguard:// URI from a generated identity, in the exact
    layout parse_wireguard_uri() already understands - so a freshly
    registered WARP peer flows through the normal parse/verify/connect
    pipeline unchanged, same as any other line from any other source."""
    host, port = identity["endpoint"].rsplit(":", 1) if ":" in identity["endpoint"] else (identity["endpoint"], "2408")
    addr = identity["address_v4"]
    if identity.get("address_v6"):
        addr += f",{identity['address_v6']}/128"
    else:
        addr += "/32"
    reserved = ",".join(str(b) for b in identity["reserved"])
    priv = urllib.parse.quote(identity["private_key"], safe="")
    query = (f"address={urllib.parse.quote(addr, safe=',/:')}"
             f"&publickey={urllib.parse.quote(identity['public_key'], safe='')}"
             f"&reserved={reserved}&mtu=1280")
    return f"warp://{priv}@{host}:{port}/?{query}#{urllib.parse.quote(remark)}"


def generate_fresh_warp_uris(binary: str, count: int = 3) -> list:
    """Register up to `count` fresh WARP identities and return them as
    warp:// URI lines. Used as an extra live source for wireguard/warp
    protocol search, on top of (not instead of) the static repo feeds."""
    uris = []
    for i in range(max(1, count)):
        try:
            identity = generate_warp_wireguard_config(binary)
        except Exception:
            identity = None
        if identity:
            uris.append(_warp_identity_to_uri(identity, remark=f"Cloudflare WARP (auto {i + 1})"))
    return uris


FREEPROXYDB_API_URL = "https://freeproxydb.com/api/proxy/subscribe"
FREEPROXYDB_PROTOCOL_MAP = {
    "vless": "vless",
    "vmess": "vmess",
    "trojan": "trojan",
    "shadowsocks": "ss",
    "hysteria2": "hysteria2",
    "socks": "socks4,socks5",
    "http": "http",
}
FREEPROXYDB_EXTRA_CACHE_TTL = 900.0
FREEPROXYDB_MIN_REQUEST_GAP = 21.0  # public API: 3 requests/minute per IP
_FREEPROXYDB_LAST_REQUEST = 0.0
_FREEPROXYDB_RATE_LOCK = threading.Lock()

# ---- Live discovery: finds NEW GitHub repos and NEW public Telegram channels on
# demand, instead of only using the fixed T1-Tn / EXTRA feed lists above. A discovered
# source is fed through the exact same parser + real sing-box verification as every
# other source (see _protocol_plan_from_lines / _quiet_verify), so the FV quality gate,
# silent background pool-fill and result memory all apply to it unchanged. Both halves
# are independently optional and fail silently (like an empty feed) when unavailable:
# GitHub discovery works with no token (Repository Search API), and upgrades itself to
# also use the deeper Code Search API the moment a token is set. Telegram discovery
# needs a one-time login (see telegram_login.py) because finding UNKNOWN channels by
# keyword requires Telegram's own account-based global search (contacts.search); once a
# channel is known, fetching its posts already works without login (fetch_telegram_channel_configs).
GITHUB_DISCOVERY_ENABLED = True
GITHUB_TOKEN = os.environ.get("RAMIN_GITHUB_TOKEN", "")  # optional PAT (no scopes needed, public data only)
GITHUB_API_BASE = "https://api.github.com"
GITHUB_DISCOVERY_MAX_REPOS = 15         # repos inspected per query
GITHUB_DISCOVERY_MAX_FILES_PER_REPO = 4 # candidate files fetched per repo
GITHUB_DISCOVERY_CACHE_TTL = 900.0      # seconds - avoid re-searching the same query back to back
GITHUB_DISCOVERY_MIN_REQUEST_GAP = 6.5  # unauthenticated search: 10 req/min -> stay under it
GITHUB_DISCOVERY_CANDIDATE_FILES = (
    "README.md", "readme.md", "Readme.md",
    "sub.txt", "sub", "subscribe.txt", "config.txt", "configs.txt",
    "all.txt", "All_Configs_Sub.txt", "mixed.txt",
)
_GITHUB_DISCOVERY_CACHE = {}
_GITHUB_LAST_REQUEST = 0.0
_GITHUB_RATE_LOCK = threading.Lock()
DISCOVERED_SOURCES_PATH = _json_path("discovered_sources.json")  # learned-good repos/channels,
# scored and pruned the same way as source_memory.json - kept separate so a corrupt/deleted file
# only forgets discovery history, never the T1-Tn result memory.

TELEGRAM_DISCOVERY_ENABLED = True
TELEGRAM_API_ID = os.environ.get("RAMIN_TG_API_ID", "")      # from https://my.telegram.org (free)
TELEGRAM_API_HASH = os.environ.get("RAMIN_TG_API_HASH", "")
TELEGRAM_SESSION_FILE = os.path.abspath("ramin_tg.session")  # created once by telegram_login.py
TELEGRAM_DISCOVERY_MAX_CHANNELS = 6
TELEGRAM_DISCOVERY_MESSAGES_PER_CHANNEL = 150
TELEGRAM_DISCOVERY_CACHE_TTL = 900.0
_TELEGRAM_DISCOVERY_CACHE = {}

LOCAL_SOCKS_HTTP_PORT = 64808  # main port: auto-picks the best of the top N servers

# additional local SOCKS5+HTTP proxy ports - all mirror the same tunnel/route as
# the main port above, just extra entry points for apps that need a specific port
EXTRA_PORTS = [2000, 3000, 60000, 50000, 20202, 3333, 8181,
               56001, 64646, 10808, 9808, 7500, 8500]
CLASH_API_PORT = 9090  # local-only API sing-box exposes so we can read current server + ping
VERIFY_CLASH_API_PORT = 9091  # separate port for the temporary verification sing-box process -
# MUST differ from CLASH_API_PORT, since choose_servers() (which runs verify_candidates_real)
# is called BEFORE the live/previous sing-box is killed, so the live one is still holding
# CLASH_API_PORT at that moment. Reusing the same port here made the verify step's own
# temporary sing-box process fail to start, which failed EVERY candidate's check at once.
MONITOR_INTERVAL_SECONDS = 60  # how often we check whether sing-box switched servers / usage
CHECK_INTERVAL_SECONDS = 5  # how often we check whether sing-box is still alive (for fast auto-retry)
RETRY_BACKOFF_SECONDS = [5, 15, 30, 60, 120]  # increasing wait between reconnect attempts

# Shown for every "Type + Enter" search (protocol, country, ping) that comes
# back with nothing to connect to. One shared message/timing so all of them
# behave the same: show it briefly, then redraw the existing connection
# screen - never leave a stale error line sitting under the prompt.
NO_RESULTS_MESSAGE = "😔We are sorry, no results were found."
NO_RESULTS_DISPLAY_SECONDS = 2.0


class _FvRetryProcess:
    """Small local stand-in used when FV has no live connection yet.

    It lets the main loop keep accepting commands while waiting for the next
    automatic FV-only retry, without pretending that a real sing-box process
    is running and without ever invoking the S1-S8 reconnect path.
    """
    def __init__(self, delay_seconds: float):
        self.dead_at = time.monotonic() + max(0.0, float(delay_seconds))
        self.returncode = 1

    def poll(self):
        if time.monotonic() >= self.dead_at:
            return self.returncode
        return None

    def terminate(self):
        self.returncode = 1

    def kill(self):
        self.returncode = 1



# Each run/reload uses only ONE randomly-chosen subscription (see
# pick_next_sub_index()) rather than pooling all of them, so only this
# many servers (lowest latency) from THAT subscription are kept and
# tested by the 'auto' group.
TOP_N = 10
CANDIDATE_POOL_MULTIPLIER = 4  # stage-1 (TCP) keeps top_n * this many candidates for the stage-2 TLS test
ENABLE_PER_SERVER_PORTS = False  # only port 8080 will be active
PER_SERVER_BASE_PORT = 8081  # only used if ENABLE_PER_SERVER_PORTS is True

# URL sing-box uses to measure latency to each server (lightweight, globally reachable)
URLTEST_URL = "https://www.gstatic.com/generate_204"
# Selection is automatic (no manual number prompt), but sing-box itself won't
# silently re-test/switch on a timer - only the 'r' + Enter command triggers a
# fresh rescan, so you're always in control of when reconnects happen.
URLTEST_INTERVAL = "24h"
URLTEST_TOLERANCE = 100  # ms - differences smaller than this won't trigger a switch (avoids flapping)

# live stdin commands while the script is running (type one + Enter)
RESCAN_COMMANDS = {"r", "rescan", "scan"}
FREE_VLESS_COMMANDS = {"fv"}  # download + test a pool of free public servers
FV_SOURCE_COMMANDS = {f"t{i}": i - 1 for i in range(1, len(FREE_VLESS_SOURCES) + 1)}  # T1..Tn: search that Free Vless source only
# from the dedicated FV source chain (Sub1 first, then fallbacks; never S1-S8)
SUBLINK_COMMANDS = {"sl", "sublink"}
SWITCH_SUB_COMMANDS = {"ss", "switchsub", "switch_sub"}  # paste a new subscription (or single-server) link -
# saved and connected as the next "Link N" / S{...} entry
DELETE_LINK_COMMANDS = {"dl", "deletelink"}  # remove a previously added 'SL' link
SEARCH_WEB_COMMANDS = {"sw", "searchweb", "search_web"}  # show the dedicated "Search Web" prompt;
# the next line typed there is handled by the existing protocol/country/ping search (same GitHub +
# Telegram sources, same quality gate, same silent background pool-fill - nothing new is added there)

# Optional throughput-oriented transport tuning. This does NOT manufacture
# bandwidth; it asks sing-box to use connection features that can reduce
# connection/setup overhead and, where the protocol/server support it, keep
# multiple multiplexed streams active. It is OFF by default and can be toggled
# live with B1 + Enter.
def load_fast_connect_state() -> dict:
    try:
        with open(FAST_CONNECT_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"enabled": False, "tag": None, "outbound": None, "free_vless_mode": False}
        return data
    except Exception:
        return {"enabled": False, "tag": None, "outbound": None, "free_vless_mode": False}


def save_fast_connect_state(tag: str, outbound: dict, free_vless_mode: bool = False, free_source_index=None):
    if not FAST_CONNECT_ENABLED or not tag or not isinstance(outbound, dict):
        return
    try:
        with open(FAST_CONNECT_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "enabled": True,
                "tag": tag,
                "outbound": outbound,
                "free_vless_mode": bool(free_vless_mode),
                "free_source_index": free_source_index,
                # Persist the whole verified FV pool together with Fast Connect.
                # This makes the Switch Server range survive a full program restart
                # even if the auxiliary switch-server cache is unavailable.
                "free_pool": _state.get("free_verified_pool", []) if free_vless_mode else [],
            }, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def tag_is_free_source(tag) -> bool:
    """True for servers that come from the Free Vless world: T1..Tn sources (FV-...) or the
    dedicated protocol feeds (PX-...). Used to restore FV mode after a restart even when an
    older fast_connect.json saved the flag wrongly."""
    t = str(tag or "")
    return t.startswith("FV-") or t.startswith("PX-")


def set_fast_connect_enabled(enabled: bool, tag: str = None, all_outbounds: list = None):
    global FAST_CONNECT_ENABLED
    FAST_CONNECT_ENABLED = bool(enabled)
    if not FAST_CONNECT_ENABLED:
        try:
            data = load_fast_connect_state()
            data["enabled"] = False
            with open(FAST_CONNECT_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
        return
    if tag and all_outbounds:
        ob = next((o for o in all_outbounds if o.get("tag") == tag), None)
        if ob:
            save_fast_connect_state(tag, ob, _state.get("free_vless_mode", False), _state.get("free_source_index"))


def disable_speed_and_fragment():
    """FV/R always start clean: Speed Boost 1/2 and Fragment are disabled."""
    global SPEED_BOOST_ENABLED, SPEED_BOOST2_ENABLED
    SPEED_BOOST_ENABLED = False
    SPEED_BOOST2_ENABLED = False
    return None


def reset_optional_settings_for_connection():
    """Every fresh/reconnected tunnel starts completely raw.

    DNS, Speed Boost and Fragment are opt-in features. They are never
    carried implicitly into a new server/subscription connection. The user
    can enable them again explicitly from Commands after the raw tunnel is
    confirmed working - or let Auto Setting (AS) do it: while AS is ON every
    fresh connection is flagged here and gets its best Fragment + DNS picked
    automatically once it is up. ChatGPT/OpenAI routing remains part of the
    base tunnel and is therefore unaffected by this reset.
    """
    global SPEED_BOOST_ENABLED, SPEED_BOOST2_ENABLED, DNS_WINNER, DNS_DISABLED
    SPEED_BOOST_ENABLED = False
    SPEED_BOOST2_ENABLED = False
    DNS_WINNER = None
    DNS_DISABLED = True
    if AUTO_SETTING_ENABLED:
        # Auto Setting is ON: this brand-new tunnel is raw right now, so the
        # main loop must run a full AS pass (best Fragment + best DNS) on it.
        _state["as_full_pending"] = True


FAST_CONNECT_ENABLED = bool(load_fast_connect_state().get("enabled", False))

# ---- Auto Setting (AS) -------------------------------------------------------
# AS is one switch that turns three things on together and keeps them tuned:
#   * DNS          - the fastest DNS provider is raced through the live tunnel
#                    after every fresh connection and re-checked every
#                    AUTO_SETTING_INTERVAL_SECONDS (15 min);
#   * Fragment     - the best FRAGMENT_PRESETS entry is measured once per fresh
#                    connection (not every 15 min);
#   * Fast Connect - always ON while AS is ON.
# "Fresh connection" = the program was (re)started, or the server / source /
# subscription changed. It is flagged by reset_optional_settings_for_connection()
# through _state["as_full_pending"] and handled by _auto_setting_cycle(full=True).
AUTO_SETTING_PATH = _json_path("auto_setting.json")  # Auto Setting on/off, plus whether
# the one-time first-connection "Enable Auto Setting?" question has been answered already


def load_auto_setting_state() -> dict:
    try:
        with open(AUTO_SETTING_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"enabled": False, "first_run_asked": False}
        return data
    except Exception:
        return {"enabled": False, "first_run_asked": False}


def save_auto_setting_state(enabled: bool, first_run_asked: bool = True):
    try:
        with open(AUTO_SETTING_PATH, "w", encoding="utf-8") as f:
            json.dump({"enabled": bool(enabled), "first_run_asked": bool(first_run_asked)},
                      f, ensure_ascii=False, indent=2)
    except Exception:
        pass


AUTO_SETTING_ENABLED = bool(load_auto_setting_state().get("enabled", False))
if AUTO_SETTING_ENABLED:
    FAST_CONNECT_ENABLED = True  # AS ON always means Fast Connect ON (also after a restart)



def _ask_yes_no_blocking(prompt: str, invalid_hint: str = ""):
    """Show `prompt` on ONE terminal row and wait, without any timeout, until the
    user types Y/YES or N/NO. Anything else is rejected: the typed text is
    erased and the very same prompt is drawn again, so the question never
    scrolls away or disappears before it has been answered.

    Returns True (yes), False (no), or None when stdin was closed and no answer
    can ever arrive (the caller then simply asks again on the next start)."""
    sys.stdout.write(prompt)
    sys.stdout.flush()
    while True:
        try:
            raw = input_queue.get(timeout=0.5)
        except queue.Empty:
            if _STDIN_CLOSED.is_set() and input_queue.empty():
                sys.stdout.write("\n")
                sys.stdout.flush()
                return None
            continue
        answer = (raw or "").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        # Not a valid answer: the terminal echoed it and moved to the next row.
        # Go back up, wipe that row and show the same question again.
        sys.stdout.write("\x1b[1A\x1b[2K\r" + prompt)
        sys.stdout.flush()


def prompt_auto_setting_first_run(last_tag: str, all_outbounds: list) -> bool:
    """The one-time "Enable Auto Setting?" question, asked at the FIRST successful
    connection of this install. It stays on screen until the user answers Y or N,
    and is never shown again afterwards (the answer is stored in
    auto_setting.json whichever it was). Fast Connect is deliberately NOT asked
    about at start-up: it simply follows Auto Setting.

    Returns True when Auto Setting was switched ON by this answer."""
    global AUTO_SETTING_ENABLED
    if load_auto_setting_state().get("first_run_asked"):
        return False
    print(f"\n{INFO} Auto Setting = best DNS + best Fragment + Fast Connect")
    answer = _ask_yes_no_blocking(
        f"  {_C.YELLOW}{_C.BOLD}⚙ Enable Auto Setting?{_C.RESET} {_C.BOLD}[Y/N]{_C.RESET} : ")
    if answer is None:
        return False  # stdin closed: not answered, so it will be asked again next time
    AUTO_SETTING_ENABLED = bool(answer)
    save_auto_setting_state(AUTO_SETTING_ENABLED, first_run_asked=True)
    if AUTO_SETTING_ENABLED:
        set_fast_connect_enabled(True, last_tag, all_outbounds)
        _state["as_full_pending"] = True  # first connection: pick the best Fragment + DNS now
        _state["auto_dns_rejected"] = None
        print(f"{OK} Auto Setting : ON")
    else:
        print(f"{WARN} Auto Setting : OFF")
    return AUTO_SETTING_ENABLED


SPEED_BOOST_ENABLED = False
SPEED_BOOST2_ENABLED = False
SPEED_BOOST_COMMANDS = {"b1", "b", "boost", "speed"}
SPEED_BOOST2_COMMANDS = {"b2", "boost2", "speed2"}
SPEED_BOOST_MAX_CONNECTIONS = 4
SPEED_BOOST_MIN_STREAMS = 4
SPEED_BOOST2_MAX_CONNECTIONS = 8


# ---- AI Engine (command: ai) ------------------------------------------------
# One-shot local optimizer: "ai" takes over the connection search, ranks every
# candidate by MEASURED speed + everything learned so far, connects to the best
# one and then deactivates. Knowledge persists in ai_engine.json: every
# successful connection anywhere feeds it, and a quick user abandon counts
# against the pick. UDP transports (hysteria2/tuic/wireguard) start with a
# small prior edge that real measurements can confirm or overturn.
AI_COMMANDS = {"ai", "aiengine", "ai_engine"}
AI_ENGINE_PATH = _json_path("ai_engine.json")
AI_ENGINE_BUDGET = 60.0     # hard seconds for the whole test (stage 1 + stage 2)
AI_ENGINE_STAGE1 = 30.0     # stage 1: quick real-request probe of many candidates
AI_ENGINE_STOP = 12         # stage 1 stops once this many candidates pass
AI_ENGINE_MAX_PING_MS = 800 # stage 1: candidates slower than this are dropped
AI_ENGINE_TOP_QUALITY = 5   # stage 2: how many of the best get the full quality test
AI_ENGINE_CANDIDATES = 300  # max candidates collected
AI_ENGINE_LEFT_WINDOW = 900 # "user left the AI pick" feedback window (s)
AI_UDP_TRANSPORTS = {"hysteria", "hysteria2", "tuic", "wireguard"}
# After the 'ai' command has connected: Gemini picks the best DNS (UDP first, TCP only when no
# provider answered over UDP) and the best Fragment, then a silent sweep of the other sources
# runs for AI_SCAN_SECONDS. Healthy servers it finds are stored as extra Switch Server numbers
# (Switch Server holds AI_SWITCH_TARGET servers in total) and everything it learns is saved in
# ai_engine.json / source_memory.json, so the next 'ai' run starts with better sources.
AI_SCAN_SECONDS = 120.0     # length of the silent background sweep
AI_SWITCH_TARGET = 20       # Switch Server total (connected pool + servers found by the sweep)
AI_SCAN_WORKERS = 3         # temporary sing-box tests running at once (kept low: battery/heat)
AI_SCAN_BATCH = 12          # candidates handed to the workers at a time
AI_SCAN_PER_SOURCE = 36     # candidates examined per source before the next source is tried
AI_SCAN_PREFETCH = 8        # source lists downloaded in parallel at the start of the sweep
AI_KNOWN_GOOD_MAX = 40      # healthy servers remembered between runs
AI_KNOWN_GOOD_MAX_AGE = 3 * 86400

class AIEngine:
    """Persistent protocol/source learner with Bayesian shrinkage: few samples
    never dominate (prior weight = 8 virtual samples), old data decays."""
    _PRIOR_WEIGHT = 8.0
    _MAX_N = 60

    def __init__(self, path: str):
        self.path = path
        self.data = {"version": 1, "proto": {}, "source": {}, "last_pick": None}
        self._load()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict) and d.get("version") == 1:
                self.data.update(d)
        except Exception:
            pass

    def _save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False)
        except Exception:
            pass

    def proto_score(self, ptype) -> float:
        """0..1 quality belief for a protocol type (UDP ones start higher)."""
        ptype = str(ptype or "")
        prior = 0.5   # no built-in bias: only real measurements move the score
        st = self.data["proto"].get(ptype)
        if not st:
            return prior
        n, wins = max(1, int(st.get("n", 0))), int(st.get("wins", 0))
        return (wins + prior * self._PRIOR_WEIGHT) / (n + self._PRIOR_WEIGHT)

    def source_score(self, ob) -> float:
        m = re.match(r"^(FV-[A-Za-z]+\d+|PX-[^-]+|S\d+)-", str(ob.get("tag") or ""))
        st = self.data["source"].get(m.group(1) if m else "other")
        if not st:
            return 0.5
        n, wins = max(1, int(st.get("n", 0))), int(st.get("wins", 0))
        return (wins + 0.5 * self._PRIOR_WEIGHT) / (n + self._PRIOR_WEIGHT)

    def rank(self, verified: list, prefer=None):
        """verified = [(ob, delay_ms)] -> learned order. Measured latency stays
        primary; knowledge only tilts close calls (score 1.0 = 30% discount)."""
        def key(item):
            ob, ms = item
            ms = float(ms) if ms else 9999.0
            discount = 1.0 + 0.30 * (0.5 - self.proto_score(ob.get("type"))) \
                          + 0.10 * (0.5 - self.source_score(ob))
            return ms * max(0.4, discount) * (prefer(ob) if prefer else 1.0)
        return sorted(verified, key=key)

    def record(self, ob, ok: bool, save: bool = True):
        if not isinstance(ob, dict):
            return
        st = self.data["proto"].setdefault(str(ob.get("type") or "unknown"), {"n": 0, "wins": 0})
        st["n"] += 1
        if ok:
            st["wins"] += 1
        if st["n"] > self._MAX_N:          # gentle decay: recent behaviour wins
            st["n"] = int(st["n"] * 0.7)
            st["wins"] = int(st["wins"] * 0.7)
        m = re.match(r"^(FV-[A-Za-z]+\d+|PX-[^-]+|S\d+)-", str(ob.get("tag") or ""))
        sst = self.data["source"].setdefault(m.group(1) if m else "other", {"n": 0, "wins": 0})
        sst["n"] += 1
        if ok:
            sst["wins"] += 1
        if sst["n"] > self._MAX_N:
            sst["n"] = int(sst["n"] * 0.7)
            sst["wins"] = int(sst["wins"] * 0.7)
        if save:
            self._save()

    def flush(self):
        self._save()

    def remember_good(self, pairs):
        """pairs = [(outbound, delay_ms)]: healthy servers kept for the next runs (best first)."""
        now = time.time()
        by_fp = {tuple(g.get("fp", ())): g for g in self.data.get("good", []) if isinstance(g, dict)}
        for ob, ms in pairs or []:
            if not isinstance(ob, dict):
                continue
            fp = list(_ob_fingerprint(ob))
            by_fp[tuple(fp)] = {"fp": fp, "ob": dict(ob), "at": now,
                                "ms": round(float(ms)) if ms else None}
        items = [g for g in by_fp.values() if now - g.get("at", 0) < AI_KNOWN_GOOD_MAX_AGE]
        items.sort(key=lambda g: g.get("ms") or 9999)
        self.data["good"] = items[:AI_KNOWN_GOOD_MAX]
        self._save()

    def known_good(self, limit: int = 20) -> list:
        now = time.time()
        out = []
        for g in self.data.get("good", []):
            if isinstance(g, dict) and isinstance(g.get("ob"), dict) \
                    and now - g.get("at", 0) < AI_KNOWN_GOOD_MAX_AGE:
                out.append(dict(g["ob"]))
        return out[:limit]

    def record_dns(self, r: dict):
        d = self.data.setdefault("dns", {})
        key = f"{r.get('name')}|{r.get('proto')}"
        d[key] = min(int(d.get(key, 0)) + 1, 999)
        self._save()

    def dns_wins(self, r: dict) -> int:
        return int(self.data.get("dns", {}).get(f"{r.get('name')}|{r.get('proto')}", 0))

    def record_fragment(self, pid):
        d = self.data.setdefault("frag", {})
        key = str(pid or 0)
        d[key] = min(int(d.get(key, 0)) + 1, 999)
        self._save()

    def fragment_wins(self, pid) -> int:
        return int(self.data.get("frag", {}).get(str(pid or 0), 0))

    def mark_pick(self, ob):
        self.data["last_pick"] = {"fp": list(_ob_fingerprint(ob)),
                                  "proto": str(ob.get("type") or "unknown"),
                                  "at": time.time()}
        self._save()

    def record_user_left(self, new_ob=None):
        """User switched away from the AI pick shortly after: the pick takes the
        blame, the user's own choice gets credit."""
        lp = self.data.get("last_pick")
        self.data["last_pick"] = None
        self._save()
        if not lp or time.time() - lp.get("at", 0) > AI_ENGINE_LEFT_WINDOW:
            return
        new_fp = list(_ob_fingerprint(new_ob)) if isinstance(new_ob, dict) else None
        if new_fp is not None and new_fp == lp.get("fp"):
            return                          # same server re-picked - no blame
        self.record({"type": lp.get("proto"), "tag": ""}, False)
        if isinstance(new_ob, dict):
            self.record(new_ob, True)

AI = AIEngine(AI_ENGINE_PATH)


# ---- User behaviour learning (Jason/user_behavior.json) ---------------------------
# The program watches what the USER does - which protocols and countries they type, which
# ping they ask for, which sources they use, and (Switch Server) what they were looking for
# when they left one server for another - and stores it in Jason/user_behavior.json (created
# at the very first start, human readable). The AI Engine (`ai`) reads it and works the way
# this user usually wants: candidates are tested in the order the habits favour, the ranking
# gets a bonus for the usual protocol / country / speed, the ping ceiling follows the user's
# usual ping, the background sweep looks in the preferred protocol's feeds first, and Gemini
# receives a small anonymous profile (protocol names, country codes, numbers - never servers).
# Old habits fade (every new event shrinks the older ones), and the influence grows with
# the number of events: nothing at first, full weight after 10 events.
USER_BEHAVIOR_PATH = _json_path("user_behavior.json")


def _median(vals):
    v = sorted(x for x in vals if x is not None)
    if not v:
        return None
    n = len(v)
    return v[n // 2] if n % 2 else (v[n // 2 - 1] + v[n // 2]) / 2.0


class UserBehavior:
    _DECAY = 0.95
    _MAX_LOG = 200
    _MAX_KEYS = 30

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self.data = {
            "version": 1,
            "stats": {"events": 0, "searches": 0, "switches": 0, "ai_runs": 0, "ai_overridden": 0},
            "protocol": {}, "country": {}, "source": {}, "flag": {}, "text": {}, "intent": {},
            "ping_requests": [], "picked_ping_ms": [], "picked_kbps": [], "log": [],
        }
        self._load()
        if not os.path.exists(self.path):
            self._save()          # the file exists from the very first start

    # ---- storage ---------------------------------------------------------------
    def _load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
            if not isinstance(d, dict):
                return
            for k, default in list(self.data.items()):
                v = d.get(k)
                if isinstance(v, type(default)):
                    if isinstance(default, dict) and k == "stats":
                        default.update({a: b for a, b in v.items() if isinstance(b, (int, float))})
                    else:
                        self.data[k] = v
        except Exception:
            pass

    def _save(self):
        try:
            with self._lock:
                out = dict(self.data)
                out["summary"] = self._summary_dict()
                out["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
                tmp = self.path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(out, f, ensure_ascii=False, indent=1)
                os.replace(tmp, self.path)
        except Exception:
            pass

    # ---- helpers -----------------------------------------------------------------
    def _bump(self, cat: str, key: str, w: float = 1.0):
        d = self.data.setdefault(cat, {})
        for k in list(d):
            d[k] *= self._DECAY
            if d[k] < 0.05:
                del d[k]
        d[key] = round(d.get(key, 0.0) + w, 4)
        if len(d) > self._MAX_KEYS:
            for k, _v in sorted(d.items(), key=lambda kv: kv[1])[:len(d) - self._MAX_KEYS]:
                del d[k]

    def _push(self, name: str, value, cap: int = 20):
        lst = self.data.setdefault(name, [])
        lst.append(value)
        del lst[:-cap]

    def _log(self, **kw):
        kw["t"] = int(time.time())
        lst = self.data.setdefault("log", [])
        lst.append(kw)
        del lst[:-self._MAX_LOG]

    def share(self, cat: str, key) -> float:
        d = self.data.get(cat) or {}
        tot = sum(d.values())
        return (d.get(key, 0.0) / tot) if tot > 0 else 0.0

    def top(self, cat: str, n: int = 3) -> list:
        d = self.data.get(cat) or {}
        tot = sum(d.values())
        if tot <= 0:
            return []
        return [(k, v / tot) for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:n]]

    def events(self) -> int:
        return int(self.data["stats"].get("events", 0))

    def confidence(self) -> float:
        """0 = nothing learned yet ... 1 = 10+ events: how much the habits are trusted."""
        return min(1.0, self.events() / 10.0)

    def top_protocol(self, min_share: float = 0.4, min_events: int = 3):
        if self.events() < min_events:
            return None
        t = self.top("protocol", 1)
        return t[0][0] if t and t[0][1] >= min_share else None

    def top_country(self, min_share: float = 0.4, min_events: int = 3):
        if self.events() < min_events:
            return None
        t = self.top("country", 1)
        return t[0][0] if t and t[0][1] >= min_share else None

    def typical_ping(self):
        """The ping (ms) this user usually wants: the median of the pings they ask for (P<n>),
        otherwise 1.3x the median ping of the servers they pick by hand."""
        req = _median(self.data.get("ping_requests"))
        if req is not None and len(self.data["ping_requests"]) >= 2:
            return req
        pk = self.data.get("picked_ping_ms") or []
        if len(pk) >= 3:
            return _median(pk) * 1.3
        return None

    def typical_kbps(self):
        pk = self.data.get("picked_kbps") or []
        return _median(pk) if len(pk) >= 2 else None

    def ping_ceiling(self, default: float) -> float:
        tp = self.typical_ping()
        if tp is None or self.confidence() < 0.3:
            return default
        return max(300.0, min(float(default), tp * 1.6))

    # ---- recording (never raises) ---------------------------------------------------
    def record_search(self, protocol=None, country=None, ping_ms=None, udp=False,
                      source=None, text=None):
        try:
            with self._lock:
                st = self.data["stats"]
                st["events"] += 1
                st["searches"] += 1
                if protocol:
                    self._bump("protocol", str(protocol))
                if country:
                    self._bump("country", str(country).upper())
                if ping_ms:
                    self._push("ping_requests", int(ping_ms))
                if udp:
                    self._bump("flag", "udp")
                if source:
                    self._bump("source", str(source))
                if text:
                    for w in str(text).lower().split()[:6]:
                        self._bump("text", w[:20], 0.5)
                self._log(kind="search", protocol=protocol, country=country, ping_ms=ping_ms,
                          udp=bool(udp) or None, source=source, text=(str(text)[:40] if text else None))
            self._save()
        except Exception:
            pass

    def mark_ai_run(self):
        try:
            with self._lock:
                self.data["stats"]["ai_runs"] += 1
            self._save()
        except Exception:
            pass

    def record_switch(self, old: dict, new: dict, number=None):
        """A Switch Server pick. `old` = the server the user left (protocol, measured ping, exit
        country, whether it was the AI's pick), `new` = the one they chose. What the user was
        looking for is derived from what changed."""
        try:
            old, new = old or {}, new or {}
            from_ai = bool(old.get("from_ai"))
            intents = []
            op, npg = old.get("ping_ms"), new.get("ping_ms")
            if old.get("tag"):
                if op is None:
                    intents.append("dead_connection")
                elif npg is not None and op > 250 and npg < op * 0.75:
                    intents.append("lower_ping")
                if old.get("protocol") and new.get("protocol") and old["protocol"] != new["protocol"]:
                    intents.append("protocol")
                if old.get("country") and new.get("country") and old["country"] != new["country"]:
                    intents.append("country")
            if not intents:
                intents.append("speed_or_stability")
            w = 0.3 if intents == ["dead_connection"] else 1.0   # "the next number" says little
            if from_ai:
                w *= 2.0                                          # overriding the AI says a lot
            with self._lock:
                st = self.data["stats"]
                st["events"] += 1
                st["switches"] += 1
                if from_ai:
                    st["ai_overridden"] += 1
                if new.get("protocol"):
                    self._bump("protocol", new["protocol"], w)
                if new.get("country"):
                    self._bump("country", new["country"], w)
                for it in intents:
                    self._bump("intent", it, 1.0)
                if npg is not None:
                    self._push("picked_ping_ms", round(npg))
                self._log(kind="switch", number=number, from_ai=from_ai or None, intents=intents,
                          old={k: old.get(k) for k in ("protocol", "ping_ms", "country")},
                          new={k: new.get(k) for k in ("protocol", "ping_ms", "country")})
            self._save()
        except Exception:
            pass

    def note_speed(self, tag, kbps):
        """Throughput measured (in the background) on the server the user picked by hand."""
        try:
            with self._lock:
                self._push("picked_kbps", round(float(kbps)))
                for e in reversed(self.data.get("log", [])):
                    if e.get("kind") == "switch":
                        e["kbps"] = round(float(kbps))
                        break
            self._save()
        except Exception:
            pass

    # ---- using what was learned --------------------------------------------------------
    def prefer_fn(self, metrics: dict = None, verified_country=None):
        """Returns f(ob) -> multiplier in [0.55, 1.0] for the AI ranking (lower = better fit)."""
        metrics = metrics or {}
        vc = verified_country or set()
        conf = self.confidence()
        if conf <= 0:
            return lambda ob: 1.0
        countries = self.top("country", 2)
        top_cc = self.top_country()
        tk = self.typical_kbps()
        udp_share = self.share("flag", "udp")

        def f(ob):
            typ = str(ob.get("type") or "")
            tag = str(ob.get("tag") or "")
            bonus = 0.30 * self.share("protocol", typ)
            if typ in UDP_CAPABLE_PROTOCOLS:
                bonus += 0.10 * udp_share
            cshare = 0.0
            if tag in vc and top_cc:
                cshare = self.share("country", top_cc)          # exit country really verified
            else:
                for code, sh in countries:                       # only a hint from the config's name
                    try:
                        if _remark_matches_country(tag, code):
                            cshare = max(cshare, sh * 0.6)
                    except Exception:
                        pass
            bonus += 0.25 * cshare
            try:
                src = (connect_source_label(tag) or "").split("_")[0]
                if src:
                    bonus += 0.10 * self.share("source", src)
            except Exception:
                pass
            kb = (metrics.get(ob.get("tag")) or {}).get("kbps")
            if tk and kb and kb >= 0.8 * tk:
                bonus += 0.10
            return max(0.55, 1.0 - conf * bonus)
        return f

    def _summary_dict(self) -> dict:
        return {
            "events": self.events(),
            "confidence": round(self.confidence(), 2),
            "protocols": {k: round(v, 2) for k, v in self.top("protocol", 3)},
            "countries": {k: round(v, 2) for k, v in self.top("country", 3)},
            "sources": {k: round(v, 2) for k, v in self.top("source", 3)},
            "udp_share": round(self.share("flag", "udp"), 2),
            "typical_ping_ms": (round(self.typical_ping()) if self.typical_ping() else None),
            "typical_kbps": (round(self.typical_kbps()) if self.typical_kbps() else None),
            "switch_intents": {k: round(v, 2) for k, v in self.top("intent", 3)},
        }

    def gemini_profile(self):
        """Small anonymous profile for Gemini (None until 3 events exist)."""
        if self.events() < 3:
            return None
        sm = self._summary_dict()
        st = self.data["stats"]
        sm["ai_overridden_ratio"] = round(st.get("ai_overridden", 0) / max(1, st.get("ai_runs", 0)), 2)
        sm.pop("sources", None)
        return sm

    def summary_line(self):
        if self.events() < 3:
            return None
        parts = [f"{k} {round(v * 100)}%" for k, v in self.top("protocol", 2)]
        parts += [f"{k} {round(v * 100)}%" for k, v in self.top("country", 2)]
        tp = self.typical_ping()
        if tp:
            parts.append(f"ping ~{round(tp)}ms")
        it = self.top("intent", 1)
        if it:
            parts.append(f"switches for: {it[0][0]}")
        return ("learned from you (" + str(self.events()) + " events): " + " · ".join(parts)) if parts else None


UB = UserBehavior(USER_BEHAVIOR_PATH)


def _quick_ping_ms(timeout: float = 2.0):
    """One real request through the live tunnel: ms, or None (dead / too slow)."""
    purl = f"http://127.0.0.1:{LOCAL_SOCKS_HTTP_PORT}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": purl, "https": purl}))
    t0 = time.monotonic()
    try:
        req = urllib.request.Request(URLTEST_URL, method="HEAD", headers={"Cache-Control": "no-cache"})
        with opener.open(req, timeout=timeout) as r:
            r.read(1)
        return (time.monotonic() - t0) * 1000.0
    except Exception:
        return None


def _ub_describe(tag, all_outbounds, top_outbounds, with_ping: bool) -> dict:
    ob = next((o for o in list(top_outbounds or []) + list(all_outbounds or []) if o.get("tag") == tag), None)
    info = {"tag": tag, "protocol": (str(ob.get("type")) if ob else None), "ping_ms": None,
            "country": None, "udp": bool(ob and str(ob.get("type")) in UDP_CAPABLE_PROTOCOLS)}
    ic = _state.get("info_cache")
    try:
        if tag and ic and ic.get("key") and ic["key"][0] == tag and isinstance(ic.get("info"), dict):
            cc = str(ic["info"].get("countryCode") or "").upper()
            info["country"] = cc if len(cc) == 2 else None
    except Exception:
        pass
    if with_ping and tag:
        info["ping_ms"] = _quick_ping_ms(2.0)
    return info


def ub_capture_before_switch(last_tag, all_outbounds, top_outbounds) -> dict:
    """Call right BEFORE a Switch Server pick: what the user is leaving (protocol, real ping,
    exit country, was it the AI's pick?). At most ~2 seconds when the old tunnel is dead."""
    try:
        info = _ub_describe(last_tag, all_outbounds, top_outbounds, with_ping=bool(last_tag))
        lp = AI.data.get("last_pick")
        info["from_ai"] = bool(lp and time.time() - lp.get("at", 0) <= AI_ENGINE_LEFT_WINDOW
                               and _state.get("ai_tag") and _state.get("ai_tag") == last_tag)
        return info
    except Exception:
        return {}


def ub_record_after_switch(old: dict, new_tag, all_outbounds, top_outbounds, number=None):
    """Call right AFTER the switch connected: the behaviour is recorded at once, the speed of the
    new server is measured in the background (one small download) and added a moment later."""
    try:
        new = _ub_describe(new_tag, all_outbounds, top_outbounds, with_ping=True)
        UB.record_switch(old, new, number=number)
    except Exception:
        return

    def _speed():
        try:
            purl = f"http://127.0.0.1:{LOCAL_SOCKS_HTTP_PORT}"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": purl, "https": purl}))
            kbps, _err = _fv_quality_download(opener)
            if kbps:
                UB.note_speed(new_tag, kbps)
        except Exception:
            pass
    threading.Thread(target=_speed, daemon=True).start()


def _ub_order_candidates(cands: list) -> list:
    """Learned habits decide the TESTING order: 3 of every 4 slots go to candidates the user's
    habits favour, every 4th stays random so the AI keeps exploring."""
    if UB.confidence() < 0.3 or len(cands) < 8:
        return cands
    f = UB.prefer_fn()
    head = sorted([ob for ob in cands if f(ob) < 1.0], key=f)
    if not head:
        return cands
    rest = [ob for ob in cands if f(ob) >= 1.0]        # keeps the shuffled order
    out, hi, ri = [], 0, 0
    while hi < len(head) or ri < len(rest):
        for _ in range(3):
            if hi < len(head):
                out.append(head[hi])
                hi += 1
        if ri < len(rest):
            out.append(rest[ri])
            ri += 1
    return out


# ---- Gemini connection for the AI Engine --------------------------------------
# The 'ai' command measures candidates locally (real sing-box requests), then asks
# Gemini to judge the MEASURED results and order them. Gemini only ever sees
# anonymous ids (c1, c2...) with numbers - never addresses, keys, UUIDs or links -
# and it can only choose among servers that already passed the real tests, so a
# wrong answer can never connect you to an untested server. No key / no network /
# bad answer = the local AI ranking is used unchanged.
# Key: env RAMIN_GEMINI_API_KEY, or a one-line file  Jason/gemini_api_key.txt
# (free key: https://aistudio.google.com/apikey)
# NOTE: the function names claude_ready / prompt_claude_key / claude_rank_candidates
# are kept on purpose so connect_by_ai() and main() work unchanged.
GEMINI_MODEL = os.environ.get("RAMIN_GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
# Keys that start with "AQ." are Google Cloud / Vertex AI express keys: they are tried on the
# Vertex endpoint too. Normal AI Studio keys ("AIza...") use the first URL only.
GEMINI_VERTEX_URL = "https://aiplatform.googleapis.com/v1/publishers/google/models/{model}:generateContent"
CLAUDE_TIMEOUT = 25.0
GEMINI_KEY_FILE = _json_path("gemini_api_key.txt")
CLAUDE_SYSTEM = (
    "You are the server-selection engine of a VPN client. You receive measured results for "
    "candidate proxy servers (anonymous ids). Rank them best-first for everyday use: "
    "prefer stability (few failed probes, small gap between median and worst latency) and real "
    "download speed over raw lowest latency; treat missing metrics as unknown, not as good. "
    "If the input has a user_profile (what this user usually looks for: protocols, countries, the ping and "
    "speed they choose, why they switch servers), prefer candidates that match it (see pref_match), but never "
    "a clearly unstable one. "
    "Use ONLY the ids you were given. Reply with ONLY compact JSON, no markdown: "
    '{"order":["c2","c1"],"reason":"one short sentence in Persian"}'
)


def _gemini_api_key() -> str:
    key = os.environ.get("RAMIN_GEMINI_API_KEY", "").strip()
    if key:
        return key
    try:
        with open(GEMINI_KEY_FILE, "r", encoding="utf-8") as f:
            return f.readline().strip()
    except Exception:
        return ""


def claude_ready() -> bool:          # name kept: used by main()/connect_by_ai()
    return bool(_gemini_api_key())


def prompt_claude_key() -> bool:     # name kept: used by main()
    """Shown by the 'ai' command when no Gemini API key is stored yet: a small box, then
    "Gemini API key :" - the pasted key is saved to Jason/gemini_api_key.txt (owner-only
    permissions) and used from then on. An empty line skips Gemini for this run only.
    Returns True when a key is now available."""
    if claude_ready():
        return True
    w = max(24, min(44, term_width() - 4))
    title = "Gemini API key"
    hint = "Paste your key (Enter = skip Gemini)"
    print()
    print(f"  {_C.BLUE}{_C.BOLD}\u256d{'\u2500' * w}\u256e{_C.RESET}")
    print(f"  {_C.BLUE}{_C.BOLD}\u2502{_C.RESET}{_C.BOLD}{title.center(w)}{_C.RESET}{_C.BLUE}{_C.BOLD}\u2502{_C.RESET}")
    print(f"  {_C.BLUE}{_C.BOLD}\u2502{_C.RESET}{_fit_to_width(hint, w).center(w)}{_C.BLUE}{_C.BOLD}\u2502{_C.RESET}")
    print(f"  {_C.BLUE}{_C.BOLD}\u2570{'\u2500' * w}\u256f{_C.RESET}")
    print(f"  {_C.BOLD}{_C.CYAN}Gemini API key : {_C.RESET}", end="", flush=True)
    try:
        raw = input_queue.get()
    except Exception:
        raw = ""
    _drain_stale_input_queue()
    key = (raw or "").strip().strip("\"'")
    if not key:
        print(f"{WARN} No key entered - using the local AI only.")
        return False
    if not key.startswith(("AIza", "AQ.")) or len(key) < 20 or any(c.isspace() for c in key):
        print(f"{WARN} That doesn't look like a Gemini API key (it should start with AIza or AQ.). Not saved.")
        return False
    try:
        os.makedirs(os.path.dirname(GEMINI_KEY_FILE), exist_ok=True)
        with open(GEMINI_KEY_FILE, "w", encoding="utf-8") as f:
            f.write(key + "\n")
        try:
            os.chmod(GEMINI_KEY_FILE, 0o600)
        except Exception:
            pass
    except Exception as e:
        print(f"{WARN} Could not save the key ({e}) - using it for this run only.")
        os.environ["RAMIN_GEMINI_API_KEY"] = key
        return True
    print(f"{OK} Key saved: {os.path.relpath(GEMINI_KEY_FILE)}")
    return True


def _claude_ask(system: str, user: str, max_tokens: int = 600):   # name kept
    """One Gemini generateContent call. Tries through the active tunnel first (the API
    can be filtered directly), then direct. Returns the reply text or None."""
    key = _gemini_api_key()
    if not key:
        return None
    gen_cfg = {
        "maxOutputTokens": max_tokens,
        "temperature": 0.2,
        "responseMimeType": "application/json",
    }
    if "pro" not in GEMINI_MODEL.lower():
        # no hidden "thinking" tokens eating the reply (Pro models cannot disable thinking)
        gen_cfg["thinkingConfig"] = {"thinkingBudget": 0}
    body = json.dumps({
        "systemInstruction": {"parts": [{"text": system}]},
        "contents": [{"role": "user", "parts": [{"text": user}]}],
        "generationConfig": gen_cfg,
    }).encode("utf-8")
    headers = {"content-type": "application/json", "x-goog-api-key": key}
    urls = [GEMINI_API_URL.format(model=GEMINI_MODEL)]
    if key.startswith("AQ."):
        urls.append(GEMINI_VERTEX_URL.format(model=GEMINI_MODEL))
    order = [True, False] if _local_tunnel_up(refresh=0) else [False, True]
    for url in urls:
        for via_proxy in order:
            try:
                req = urllib.request.Request(url, data=body, headers=headers, method="POST")
                with _proxied_opener(via_proxy).open(req, timeout=CLAUDE_TIMEOUT) as resp:
                    data = json.loads(resp.read().decode("utf-8", "replace"))
                parts = (((data.get("candidates") or [{}])[0]).get("content") or {}).get("parts") or []
                text = "".join(p.get("text", "") for p in parts)
                if text:
                    return text
            except Exception:
                continue
    return None


CLAUDE_TUNE_SYSTEM = (
    "You are the network-tuning engine of a VPN client. You receive MEASURED results for one kind "
    "of setting (DNS providers, or TLS-fragment presets) as anonymous ids. Rank them best-first for "
    "reliable everyday browsing: prefer zero failures and low latency; a latency difference under "
    "about 15% does not matter, in that case prefer the entry with more past_wins. "
    "Use ONLY the ids you were given. Reply with ONLY compact JSON, no markdown: "
    '{"order":["d2","d1"],"reason":"one short sentence in Persian"}'
)


def claude_rank_rows(system: str, rows: list):
    """Generic Gemini ranking of measured rows (anonymous ids). (ordered ids, reason) or (None, None)."""
    if len(rows) < 2:
        return None, None
    text = _claude_ask(system, json.dumps(rows, ensure_ascii=False))
    if not text:
        return None, None
    try:
        m = re.search(r"\{.*\}", text, re.S)
        data = json.loads(m.group(0)) if m else {}
        valid = {r["id"] for r in rows}
        order = list(dict.fromkeys(i for i in data.get("order", []) if i in valid))
        if not order:
            return None, None
        return order, str(data.get("reason") or "")[:160]
    except Exception:
        return None, None


def claude_rank_candidates(rows: list, profile: dict = None):   # name kept
    """rows = [{"id","proto","source","ping_ms","median_ms","worst_ms","kbps","fails","learned"}, ...]
    Returns (ordered ids, reason) or (None, None)."""
    if len(rows) < 2:
        return None, None
    payload = rows if not profile else {"user_profile": profile, "candidates": rows}
    text = _claude_ask(CLAUDE_SYSTEM, json.dumps(payload, ensure_ascii=False))
    if not text:
        return None, None
    try:
        m = re.search(r"\{.*\}", text, re.S)
        data = json.loads(m.group(0)) if m else {}
        valid = {r["id"] for r in rows}
        order = [i for i in data.get("order", []) if i in valid]
        order = list(dict.fromkeys(order))
        if not order:
            return None, None
        return order, str(data.get("reason") or "")[:160]
    except Exception:
        return None, None



TELEGRAM_PREVIEW_RE = re.compile(r"(?:https?://)?t\.me/s/([A-Za-z0-9_]+)", re.IGNORECASE)
_TG_POST_ID_RE = re.compile(r'data-post="[^"/]*/(\d+)"')  # each message div's own id,
# used to page backward through OLDER messages (Telegram's ?before=<id>) when the
# most recent ~20 (the base /s/ page) don't happen to contain a config link.

# Matches any supported proxy URI embedded in raw Telegram preview-page HTML
# (either as plain text between message bubbles, or inside <code>/<a> tags).
# Built lazily off SUPPORTED_PROXY_SCHEMES further down so the two lists never
# drift apart; see _proxy_uri_pattern().
_PROXY_URI_PATTERN = None


def _proxy_uri_pattern():
    global _PROXY_URI_PATTERN
    if _PROXY_URI_PATTERN is None:
        schemes = "|".join(re.escape(s.rstrip("://")) for s in SUPPORTED_PROXY_SCHEMES)
        _PROXY_URI_PATTERN = re.compile(rf"(?:{schemes})://[^\s\"'<>`]+", re.IGNORECASE)
    return _PROXY_URI_PATTERN


def extract_proxy_uris_from_text(text: str) -> list:
    """Pull every vless/vmess/trojan/... URI out of arbitrary text (e.g. a
    Telegram channel's rendered HTML), de-duplicated, first-seen order kept."""
    unescaped = html_lib.unescape(text)
    seen, out = set(), []
    for m in _proxy_uri_pattern().finditer(unescaped):
        uri = m.group(0)
        # Telegram wraps URIs inside message text; a trailing ")" or similar
        # from surrounding punctuation/markdown occasionally rides along.
        uri = uri.rstrip("`).,;]\u2764\U0001f44e\U0001f680")
        if uri not in seen:
            seen.add(uri)
            out.append(uri)
    return out


def _proxied_opener(via_proxy: bool):
    """One local-proxy-aware urllib opener, shared by every subscription/Telegram
    fetch (and by _fetch_text_silent further down) so "try through the active
    tunnel, then direct" is the SAME behavior everywhere a config source is
    fetched - not just for the protocol-search feeds."""
    if via_proxy:
        purl = f"http://127.0.0.1:{LOCAL_SOCKS_HTTP_PORT}"
        handler = urllib.request.ProxyHandler({"http": purl, "https": purl})
    else:
        handler = urllib.request.ProxyHandler({})
    return urllib.request.build_opener(handler)


def fetch_telegram_channel_recent_posts(url: str, via_proxy: bool = False,
                                        target_posts: int = 50, max_pages: int = 6) -> str:
    """Read a Telegram channel's ~target_posts most recent messages (Telegram
    shows ~20 per page, so this pages backward with ?before=<id> until that
    many distinct messages have been seen) and return every proxy config URI
    found among them, one per line.

    Unlike fetch_telegram_channel_configs() above - which stops at the very
    first page that has ANY config, to answer "does this channel have
    something" as cheaply as possible - this always covers the full requested
    depth, so a channel that spreads several config posts across its recent
    history (not just the newest page) doesn't have any of them missed. Used
    for an explicit SW '@channel' query, where the user named this exact
    channel and thoroughness matters more than a fast first hit.
    """
    base = url.split("?", 1)[0]
    before = None
    seen_ids, collected = set(), []
    for _ in range(max(1, max_pages)):
        page_url = base if before is None else f"{base}?before={before}"
        req = urllib.request.Request(page_url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        })
        with _proxied_opener(via_proxy).open(req, timeout=15) as resp:
            raw = resp.read()
        page = raw.decode("utf-8", errors="ignore")
        collected.extend(extract_proxy_uris_from_text(page))
        ids = [int(m) for m in _TG_POST_ID_RE.findall(page)]
        if not ids:
            break  # no messages at all (empty/unknown channel, or preview disabled)
        seen_ids.update(ids)
        if len(seen_ids) >= target_posts:
            break
        earliest = min(ids)
        if before is not None and earliest >= before:
            break  # no progress - would loop forever otherwise
        before = earliest
    seen, out = set(), []
    for uri in collected:
        if uri not in seen:
            seen.add(uri)
            out.append(uri)
    return "\n".join(out)


def fetch_telegram_channel_configs(url: str, via_proxy: bool = False, max_pages: int = 3) -> str:
    """Fetch a public Telegram channel's web preview (t.me/s/<channel>) and
    return every proxy config URI found in its recent posts, one per line.

    No login/API token is needed: /s/ is Telegram's public, unauthenticated
    HTML preview meant for search engines, and channels that post free
    configs publish them as plain vless://, vmess://, trojan://, ss://, ...
    text right in the message, so a normal page fetch + regex is enough.

    via_proxy=True routes the fetch through the currently active tunnel's
    local proxy - needed when t.me itself is blocked directly but a working
    connection is already up (the caller decides when to try which).

    The base page only shows the channel's ~20 most recent messages. A
    channel that interleaves config drops with other posts (announcements,
    ads, unrelated messages) may not have one on that first page at all -
    so if it comes back with zero proxy URIs, this pages backward through
    OLDER messages (Telegram's own ?before=<message id> pagination, read
    off each message's own data-post id) up to max_pages times, stopping
    the moment a page actually contains something.
    """
    base = url.split("?", 1)[0]
    before = None
    for _ in range(max(1, max_pages)):
        page_url = base if before is None else f"{base}?before={before}"
        req = urllib.request.Request(page_url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        })
        with _proxied_opener(via_proxy).open(req, timeout=15) as resp:
            raw = resp.read()
        page = raw.decode("utf-8", errors="ignore")
        uris = extract_proxy_uris_from_text(page)
        if uris:
            return "\n".join(uris)
        ids = [int(m) for m in _TG_POST_ID_RE.findall(page)]
        if not ids:
            break  # no messages at all (empty/unknown channel, or preview disabled)
        earliest = min(ids)
        if before is not None and earliest >= before:
            break  # no progress - would loop forever otherwise
        before = earliest
    return ""


def fetch_subscription(url: str, via_proxy: bool = False) -> str:
    tg_match = TELEGRAM_PREVIEW_RE.search(url)
    if tg_match:
        return fetch_telegram_channel_configs(url, via_proxy=via_proxy)

    req = urllib.request.Request(url, headers={"User-Agent": "sing-box"})
    with _proxied_opener(via_proxy).open(req, timeout=15) as resp:
        raw = resp.read()

    # Prefer ordinary URI text when the response already contains supported
    # proxy schemes. Other sources publish base64, so decode only when the
    # response is not already recognizable as a URI subscription.
    text = raw.decode("utf-8", errors="ignore").lstrip("\ufeff")
    if any(scheme in text.lower() for scheme in SUPPORTED_PROXY_SCHEMES):
        return text
    try:
        padded = raw + b"=" * (-len(raw) % 4)
        return base64.b64decode(padded, validate=True).decode("utf-8", errors="ignore").lstrip("\ufeff")
    except Exception:
        return text


UDP_ONLY_TYPES = {"hysteria", "hysteria2", "wireguard", "tuic"}  # protocols that tunnel over QUIC/UDP,
# not TCP - the raw TCP/TLS probes in rank_and_select_top() can't test these at
# all (a plain socket connect to their port proves nothing about a QUIC
# server), so they skip straight to the real end-to-end check in
# verify_candidates_real(), which actually speaks their protocol via sing-box.

SUPPORTED_PROXY_SCHEMES = (
    "vless://", "trojan://", "hysteria2://", "hy2://", "hysteria://", "hy://",
    "warp://", "wireguard://", "vmess://", "ss://", "tuic://",
    "shadowtls://", "anytls://", "naive://", "naive+https://",
    "naive+quic://", "ssh://", "snell://", "socks://", "socks4://", "socks4a://",
    "socks5://", "http://", "https://",
)  # every scheme parse_proxy_uri() can turn into an outbound - used to filter
# lines out of mixed-protocol subscription/aggregator text (see
# fetch_free_vless_pool()) before bothering to parse each one individually.


def measure_tcp_latency(address: str, port: int, timeout: float = 3.0):
    """Stage 1: raw TCP connect time - fast, used to narrow down the full list."""
    start = time.monotonic()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return time.monotonic() - start
    except Exception:
        return None


def measure_real_latency(ob: dict, timeout: float = 5.0):
    """Stage 2: a REAL health check - full TCP connect + TLS handshake (when the
    server uses TLS, which almost all VLESS servers do). This actually proves the
    server is alive and terminating TLS correctly, unlike a plain TCP connect
    which can succeed even for a dead/misconfigured backend behind a CDN."""
    address = ob["server"]
    port = ob["server_port"]
    tls_cfg = ob.get("tls")

    start = time.monotonic()
    try:
        if isinstance(tls_cfg, dict) and tls_cfg.get("enabled"):
            sni = tls_cfg.get("server_name") or address
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((address, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni):
                    pass
        else:
            with socket.create_connection((address, port), timeout=timeout):
                pass
        return time.monotonic() - start
    except Exception:
        return None


def rank_and_select_top(outbounds: list, top_n: int, tcp_label: str = "TCP check",
                         tls_label: str = "TLS check") -> list:
    """Returns a list of (outbound, latency_seconds) tuples, sorted best-first.

    QUIC/UDP-based outbounds (Hysteria, Hysteria2 - see UDP_ONLY_TYPES) are
    split off up front: a raw TCP connect or TLS handshake to their port
    proves nothing about a QUIC server, so probing them the same way as
    VLESS/Trojan would just mark every one of them as dead. They skip
    straight through to verify_candidates_real() instead, which drives a
    real sing-box process and so actually speaks their protocol.
    """
    tcp_capable = [ob for ob in outbounds if ob.get("type") not in UDP_ONLY_TYPES]
    udp_only = [ob for ob in outbounds if ob.get("type") in UDP_ONLY_TYPES]

    tcp_results = []
    with ProgressBar(tcp_label, total=len(tcp_capable)) as pb:
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ob = {
                executor.submit(measure_tcp_latency, ob["server"], ob["server_port"]): ob
                for ob in tcp_capable
            }
            for future in concurrent.futures.as_completed(future_to_ob):
                ob = future_to_ob[future]
                latency = future.result()
                if latency is not None:
                    tcp_results.append((ob, latency))
                pb.tick()

    if not tcp_results and not udp_only:
        return []

    tcp_results.sort(key=lambda x: x[1])
    pool_size = min(len(tcp_results), top_n * CANDIDATE_POOL_MULTIPLIER)
    candidates = [ob for ob, _ in tcp_results[:pool_size]]

    real_results = []
    with ProgressBar(tls_label, total=len(candidates)) as pb:
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            future_to_ob = {
                executor.submit(measure_real_latency, ob): ob for ob in candidates
            }
            for future in concurrent.futures.as_completed(future_to_ob):
                ob = future_to_ob[future]
                latency = future.result()
                if latency is not None:
                    real_results.append((ob, latency))
                pb.tick()

    real_results.sort(key=lambda x: x[1])
    # Placeholder delay for UDP-only entries - meaningless for sorting
    # purposes (they haven't been measured yet), but this list only decides
    # which candidates get forwarded into verify_candidates_real(); the
    # actual displayed ping always comes from that real, protocol-correct
    # check, which re-sorts everything afterwards.
    udp_results = [(ob, 0.0) for ob in udp_only]
    return real_results + udp_results


VERIFY_MAX_CANDIDATES = 150  # normal startup cap; Free Vless explicitly overrides this and verifies every candidate
VERIFY_TIMEOUT_MS = 5000



def _build_verify_config(outbounds, api_port):
    """Build a minimal sing-box config used only by FV/SubLink verification."""
    return apply_endpoints({
        "log": {"level": "fatal"},
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{api_port}"
            }
        },
        "inbounds": [],
        # WireGuard records are moved into "endpoints" by apply_endpoints():
        # the WireGuard *outbound* no longer exists since sing-box 1.13.
        "outbounds": [dict(o) for o in outbounds] + [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct", "default_domain_resolver": "dns-direct"},
        # sing-box 1.12+ refuses to start at all without a domain resolver
        # declared somewhere - without this, every candidate whose server
        # is a hostname (not a bare IP) makes sing-box exit immediately,
        # which looks like "every server is dead" even when none are.
        "dns": {
            "servers": [{"type": "https", "tag": "dns-direct", "server": "1.1.1.1"}],
            "final": "dns-direct",
            "strategy": "prefer_ipv4",
        },
    })


def _singbox_check_config(binary: str, outbounds: list):
    """Return (ok, error_text) without starting a long-running sing-box."""
    path = CONFIG_PATH + ".fvcheck.json"
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(_build_verify_config(outbounds, VERIFY_CLASH_API_PORT), f)
        cp = subprocess.run(
            [binary, "check", "-c", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
        )
        output = (cp.stdout or "").strip()
        return cp.returncode == 0, output
    except Exception as e:
        return False, str(e)
    finally:
        try:
            os.remove(path)
        except Exception:
            pass


def _split_invalid_extended_batches(binary: str, outbounds: list):
    """Keep valid FV/SubLink configs even if a public subscription contains
    one or more configs using fields unsupported by the installed sing-box.

    A single bad outbound can make a large all-in-one sing-box config fail.
    We therefore validate batches and recursively split only failed batches.
    S1-S8 never call this function.
    """
    if not outbounds:
        return []

    valid = []
    pending = [outbounds]
    first_error = None

    while pending:
        batch = pending.pop()
        ok, err = _singbox_check_config(binary, batch)
        if ok:
            valid.extend(batch)
            continue

        if first_error is None:
            first_error = err

        if len(batch) == 1:
            continue

        mid = len(batch) // 2
        pending.append(batch[mid:])
        pending.append(batch[:mid])

    return valid


def _get_free_local_port() -> int:
    """Ask the OS for a currently free loopback TCP port.

    Used only by the FV/SubLink verifier so each temporary sing-box process
    gets its own Clash API port.  S1-S8 never use this path.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


_VERIFY_CONFIG_MAX_AGE_SECONDS = 600.0    # a leftover .fvone./.frag. file older than this is safe to remove
_VERIFY_CONFIG_CLEANUP_EVERY = 3600.0     # ...checked at most once an hour while the program runs


def cleanup_stale_verify_configs(min_age_seconds: float = None) -> int:
    """Delete leftover per-candidate sing-box configs (singbox-config.json.fvone.*.json and
    .frag.*.json - one is written per verification, in the SAME folder as the main config,
    and normally removed the instant that one test finishes). If the program is killed or
    crashes mid-test (very common on Android: the OS killing a backgrounded app, the person
    swiping it away, a phone reboot...) whatever was being tested at that exact moment is
    left behind forever, since nothing ever revisited it - so over time these pile up in the
    program's folder. Called once, unconditionally, at every startup (nothing from a fresh
    process's OWN testing can exist yet, so everything found there is a previous run's
    orphan) and again periodically during a long session, that time only touching files
    older than min_age_seconds so an actively-running test's own file is never touched."""
    folder = os.path.dirname(os.path.abspath(CONFIG_PATH)) or "."
    base = os.path.basename(CONFIG_PATH)
    removed = 0
    now = time.time()
    try:
        for name in os.listdir(folder):
            if not (name.startswith(f"{base}.fvone.") or name.startswith(f"{base}.frag."))                     or not name.endswith(".json"):
                continue
            path = os.path.join(folder, name)
            try:
                if min_age_seconds is not None and now - os.path.getmtime(path) < min_age_seconds:
                    continue
                os.remove(path)
                removed += 1
            except OSError:
                continue
    except OSError:
        pass
    return removed


def _verify_one_extended_candidate(binary: str, ob: dict, test_urls: list):
    """Verify exactly ONE FV/SubLink outbound with a fresh sing-box process.

    This is intentionally not a giant 500-outbound sing-box configuration.
    A single malformed/unsupported outbound, excessive startup load, or one
    broken transport must never make every other public node look dead.
    """
    tag = ob.get("tag", "candidate")
    if ob.get("type") == "wireguard":
        # WireGuard is a sing-box *endpoint* now; test it through the real
        # mixed-proxy data path instead of depending on how the Clash API
        # lists endpoints.
        ok, delay_ms, err = _verify_one_fv_sublink(binary, ob, test_urls)
        return (float(delay_ms) if ok and delay_ms is not None else None), err
    api_port = _get_free_local_port()
    tmp_path = f"{CONFIG_PATH}.fvone.{os.getpid()}.{threading.get_ident()}.{api_port}.json"
    config = _build_verify_config([ob], api_port)
    proc = None
    last_error = ""

    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)

        # Validate this candidate alone. This also gives us a useful error
        # for the first few failures instead of hiding everything in DEVNULL.
        cp = subprocess.run(
            [binary, "check", "-c", tmp_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=12,
        )
        if cp.returncode != 0:
            return None, f"config rejected: {(cp.stdout or '').strip()[:240]}"

        proc = subprocess.Popen(
            [binary, "run", "-c", tmp_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Do not assume a fixed 1.5 s startup time on Android.
        deadline = time.monotonic() + 6.0
        api_ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                err = ""
                try:
                    err = (proc.stderr.read() or "").strip()
                except Exception:
                    pass
                return None, f"sing-box exited: {err[:240]}"
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{api_port}/version", timeout=0.5
                ) as resp:
                    if resp.status == 200:
                        api_ready = True
                        break
            except Exception:
                time.sleep(0.12)

        if not api_ready:
            err = ""
            try:
                if proc.poll() is not None:
                    err = (proc.stderr.read() or "").strip()
            except Exception:
                pass
            return None, f"Clash API did not start{(': ' + err[:200]) if err else ''}"

        # This is the real protocol test: sing-box itself dials the selected
        # outbound and performs an HTTPS request through that exact proxy.
        for test_url in test_urls:
            try:
                url = (
                    f"http://127.0.0.1:{api_port}/proxies/"
                    f"{urllib.parse.quote(tag, safe='')}/delay"
                    f"?url={urllib.parse.quote(test_url, safe='')}"
                    f"&timeout={VERIFY_TIMEOUT_MS}"
                )
                started = time.monotonic()
                with urllib.request.urlopen(
                    url, timeout=(VERIFY_TIMEOUT_MS / 1000) + 2
                ) as resp:
                    data = json.loads(resp.read().decode("utf-8", "replace"))
                delay = data.get("delay")
                if isinstance(delay, (int, float)) and delay >= 0:
                    # Prefer the delay returned by sing-box because it is the
                    # protocol-aware measurement, not a Python socket ping.
                    return float(delay), None
                last_error = f"no delay in API response: {data}"
            except Exception as e:
                last_error = str(e)

        return None, last_error[:240] if last_error else "proxy test failed"

    except subprocess.TimeoutExpired:
        return None, "sing-box check timed out"
    except Exception as e:
        return None, str(e)[:240]
    finally:
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=1.5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            try:
                if proc.stderr:
                    proc.stderr.close()
            except Exception:
                pass
        try:
            os.remove(tmp_path)
        except Exception:
            pass


def verify_candidates_extended(binary: str, ranked: list, top_n: int,
                               label: str = "Verify", max_candidates: int = None,
                               test_urls: list = None) -> list:
    """FV/SubLink-only real protocol verification.

    IMPORTANT: unlike S1-S8, every FV/SubLink candidate gets its OWN temporary
    sing-box instance. We do not put hundreds of public configs into one
    sing-box configuration. This isolates bad configs and prevents one broken
    outbound or an overloaded giant config from turning the entire subscription
    into ZERO working nodes.
    """
    pool = ranked if max_candidates is None else ranked[:max_candidates]
    if not pool:
        return []

    outbounds = [ob for ob, _ in pool]
    urls_to_try = test_urls or [
        "https://www.gstatic.com/generate_204",
        "https://www.google.com/generate_204",
        "https://cp.cloudflare.com/generate_204",
    ]

    working = {}
    failures = []
    lock = threading.Lock()

    # Keep concurrency moderate for Android/Termux. Each worker owns a
    # separate sing-box process and Clash API port.
    workers = min(8, max(1, len(outbounds)))
    with ProgressBar(label, total=len(outbounds)) as pb:
        def worker(ob):
            try:
                delay, error = _verify_one_extended_candidate(binary, ob, urls_to_try)
                if delay is not None:
                    with lock:
                        working[ob["tag"]] = delay
                elif error:
                    with lock:
                        if len(failures) < 8:
                            failures.append((ob.get("tag", "?"), error))
            finally:
                pb.tick()

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            list(executor.map(worker, outbounds))

    if not working and failures:
        # Show a few real reasons only when the entire FV/SubLink set failed.
        # This makes the next diagnosis actionable without flooding the UI.
        print(f"{WARN} FV/SubLink: all candidates failed. Sample failure reasons:")
        for tag, err in failures[:3]:
            print(f"  {_C.DIM}{tag}: {err}{_C.RESET}")

    verified = [
        (ob, working[ob["tag"]] / 1000.0)
        for ob in outbounds
        if ob["tag"] in working
    ]
    verified.sort(key=lambda x: x[1])
    return verified[:top_n] if top_n else verified

def _pick_ephemeral_port():
    """Ask the OS for a currently-free localhost TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


_FV_DL_SEM = threading.Semaphore(FV_QUALITY_DL_CONCURRENCY)
_FV_TEST_PROCS = set()  # temporary verification sing-box processes still running


def kill_test_procs():
    """Terminate any temporary verification sing-box still alive (used when the
    program exits while the silent background search is in the middle of a test)."""
    for pr in list(_FV_TEST_PROCS):
        try:
            if pr.poll() is None:
                pr.kill()
        except Exception:
            pass
    _FV_TEST_PROCS.clear()


def _fv_exit_country(opener):
    """ISO country code of the exit IP of the tunnel behind `opener`, or None."""
    services = (
        ("http://ip-api.com/line/?fields=countryCode", "text"),
        ("https://ipwho.is/?fields=country_code", "json"),
        ("https://api.country.is/", "json"),
    )
    for url, kind in services:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "RaminVPN-Geo/1.0", "Cache-Control": "no-cache"})
            with opener.open(req, timeout=6) as resp:
                body = resp.read(600).decode("utf-8", errors="ignore").strip()
            if kind == "json":
                data = json.loads(body)
                cc = str(data.get("country_code") or data.get("country") or "").strip()
            else:
                cc = body.splitlines()[0].strip() if body else ""
            if len(cc) == 2 and cc.isalpha():
                return cc.upper()
        except Exception:
            continue
    return None


def _fv_quality_get_204(opener, url: str) -> float:
    """One strict probe through the candidate tunnel. Returns latency in ms.

    Unlike the quick probe, the reply must be a genuine HTTP 204: captive
    portals / hijacked nodes that answer 200 with some HTML are rejected.
    """
    t0 = time.monotonic()
    req = urllib.request.Request(
        url, headers={"User-Agent": "RaminVPN-FV-Quality/1.0", "Cache-Control": "no-cache"}
    )
    with opener.open(req, timeout=FV_QUALITY_REQ_TIMEOUT) as resp:
        status = resp.status
        resp.read(64)
    if status != 204:
        raise ValueError(f"unexpected HTTP {status}")
    return (time.monotonic() - t0) * 1000.0


def _fv_quality_download(opener):
    """Download FV_QUALITY_DL_BYTES through the tunnel. Returns (KB/s, error)."""
    last_err = "no download URL worked"
    for url in FV_QUALITY_DL_URLS:
        try:
            t0 = time.monotonic()
            deadline = t0 + FV_QUALITY_DL_TIMEOUT
            got = 0
            req = urllib.request.Request(url, headers={"User-Agent": "RaminVPN-FV-Quality/1.0"})
            with opener.open(req, timeout=FV_QUALITY_REQ_TIMEOUT) as resp:
                if resp.status != 200:
                    raise ValueError(f"HTTP {resp.status}")
                while got < FV_QUALITY_DL_BYTES:
                    if time.monotonic() > deadline:
                        raise TimeoutError("download too slow")
                    chunk = resp.read(min(32768, FV_QUALITY_DL_BYTES - got))
                    if not chunk:
                        break
                    got += len(chunk)
            elapsed = max(time.monotonic() - t0, 0.001)
            if got < FV_QUALITY_DL_BYTES * 0.9:
                raise ValueError(f"short download ({got} bytes)")
            return got / elapsed / 1024.0, None
        except Exception as e:
            last_err = str(e)
    return None, last_err


def _fv_quality_gate(opener, first_delay_ms: float, metrics: dict = None, level: int = 2):
    """Second-stage test for a candidate that already passed the quick probe.

    level 1 = stability only (repeated + simultaneous strict probes)
    level 2 = stability + download throughput test
    Returns (ok, median_latency_ms, error).
    """
    m = metrics if metrics is not None else {}
    latencies = [float(first_delay_ms)]
    fails = 0
    probe_urls = FV_QUALITY_PROBE_URLS
    n_par = max(1, min(FV_QUALITY_PARALLEL, len(probe_urls)))
    m.update(fails=0, median=float(first_delay_ms), worst=float(first_delay_ms), kbps=None)

    for r in range(FV_QUALITY_ROUNDS):
        time.sleep(FV_QUALITY_ROUND_GAP)
        urls = [probe_urls[(r + i) % len(probe_urls)] for i in range(n_par)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_par) as ex:
            futs = [ex.submit(_fv_quality_get_204, opener, u) for u in urls]
            for f in futs:
                try:
                    latencies.append(f.result())
                except Exception:
                    fails += 1
        m["fails"] = fails
        if fails > FV_QUALITY_MAX_FAILS:
            return False, None, f"unstable: {fails} probes failed"

    latencies.sort()
    median = latencies[len(latencies) // 2]
    worst = latencies[-1]
    m.update(median=median, worst=worst)
    if median > FV_QUALITY_MAX_MEDIAN_MS:
        return False, None, f"latency too high (median {median:.0f} ms)"
    if worst > FV_QUALITY_MAX_WORST_MS:
        return False, None, f"latency spikes (worst {worst:.0f} ms)"

    if level >= 2:
        with _FV_DL_SEM:
            kbps, err = _fv_quality_download(opener)
        m["kbps"] = kbps
        if kbps is None:
            return False, None, f"download failed: {err}"
        if kbps < FV_QUALITY_DL_MIN_KBPS:
            return False, None, f"too slow ({kbps:.0f} KB/s)"

    return True, median, None


def _fv_quality_level_now() -> int:
    """0 = classic quick check, 1 = + stability, 2 = + stability and download."""
    if not FV_QUALITY_MODE:
        return 0
    lvl = _state.get("fv_quality_level")
    return 2 if lvl is None else int(lvl)


UDP_CAPABLE_PROTOCOLS = {
    "vless", "vmess", "trojan", "shadowsocks", "socks", "hysteria", "hysteria2",
    "tuic", "wireguard",
}  # protocol types whose sing-box outbound can relay UDP (used by SW's "udp" search)


def _dns_query_packet(qname: str = "www.gstatic.com") -> bytes:
    """One minimal, valid DNS query (A record) - just a UDP payload to bounce off a
    public resolver through the candidate's tunnel."""
    header = b"\x12\x34" + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" * 3
    question = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname.split(".")) + b"\x00"
    question += b"\x00\x01\x00\x01"  # QTYPE=A, QCLASS=IN
    return header + question


def _socks5_udp_probe(listen_port: int, timeout: float = 4.0) -> bool:
    """True if the local mixed proxy on 127.0.0.1:listen_port can actually relay a UDP
    datagram end to end (SOCKS5 UDP ASSOCIATE + one DNS query to 1.1.1.1:53). This is the
    real test behind SW's "udp" search: it proves the candidate tunnel forwards UDP, not
    just TCP - true for hysteria2/tuic/wireguard, and for vless/vmess/trojan/ss/socks only
    when their outbound is actually relaying UDP end to end."""
    tcp = udp = None
    try:
        tcp = socket.create_connection(("127.0.0.1", listen_port), timeout=timeout)
        tcp.settimeout(timeout)
        tcp.sendall(b"\x05\x01\x00")                       # no-auth handshake
        if tcp.recv(2) != b"\x05\x00":
            return False
        tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")  # UDP ASSOCIATE, 0.0.0.0:0
        reply = tcp.recv(262)
        if len(reply) < 10 or reply[1] != 0x00:
            return False
        atyp = reply[3]
        if atyp == 0x01:
            bnd_addr = socket.inet_ntoa(reply[4:8])
            bnd_port = int.from_bytes(reply[8:10], "big")
        else:
            return False           # IPv6/domain relay address: not expected from a local proxy
        if bnd_addr in ("0.0.0.0", "127.0.0.1", ""):
            bnd_addr = "127.0.0.1"

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(timeout)
        dns_target = socket.inet_aton("1.1.1.1") + (53).to_bytes(2, "big")
        packet = b"\x00\x00\x00\x01" + dns_target + _dns_query_packet()
        udp.sendto(packet, (bnd_addr, bnd_port))
        data, _addr = udp.recvfrom(2048)
        if len(data) < 10:
            return False
        r_atyp = data[3]
        if r_atyp == 0x01:
            hdr_len = 10
        elif r_atyp == 0x04:
            hdr_len = 22
        elif r_atyp == 0x03:
            hdr_len = 7 + data[4]
        else:
            return False
        return len(data) - hdr_len >= 12   # a DNS-sized reply came back through the relay
    except Exception:
        return False
    finally:
        for s in (udp, tcp):
            try:
                if s:
                    s.close()
            except Exception:
                pass


HY2_PARROT_FALLBACK = True  # sing-box 1.14: Hysteria2 clients parrot Chrome's QUIC
# handshake by default. Chrome does not offer Ed25519, so a server that uses an
# Ed25519 certificate fails the handshake. When True, a Hysteria2 candidate that
# failed is retried once with disable_chrome_parrot=true, and the flag is kept on
# the candidate if that retry works. Set False to skip the retry (faster scans).
_HY2_NO_RETRY_PREFIXES = ("exit country", "unstable", "latency", "download failed", "too slow")


def _verify_one_fv_sublink(binary: str, ob: dict, test_urls: list, quality: int = 0, metrics: dict = None,
                           want_country: str = None, want_udp: bool = False):
    """Verify one candidate (see _verify_one_fv_sublink_once). For Hysteria2 a
    failed attempt gets one more try without Chrome QUIC parroting."""
    ok, delay, err = _verify_one_fv_sublink_once(binary, ob, test_urls, quality=quality,
                                                 metrics=metrics, want_country=want_country,
                                                 want_udp=want_udp)
    if (not ok and HY2_PARROT_FALLBACK and ob.get("type") == "hysteria2"
            and not ob.get("disable_chrome_parrot")
            and not str(err or "").lower().startswith(_HY2_NO_RETRY_PREFIXES)
            and "FATAL" not in str(err or "")):
        retry = dict(ob)
        retry["disable_chrome_parrot"] = True
        ok2, delay2, err2 = _verify_one_fv_sublink_once(binary, retry, test_urls, quality=quality,
                                                        metrics=metrics, want_country=want_country,
                                                        want_udp=want_udp)
        if ok2:
            ob["disable_chrome_parrot"] = True  # keep it for the real connection
            return ok2, delay2, err2
    return ok, delay, err


def _verify_one_fv_sublink_once(binary: str, ob: dict, test_urls: list, quality: int = 0, metrics: dict = None,
                                want_country: str = None, want_udp: bool = False):
    """Run ONE FV/SubLink outbound in its own sing-box and make a real HTTP
    request through its local mixed proxy.  This is intentionally independent
    of Clash API /delay, so sing-box 1.14.x is tested using its normal mixed
    inbound and ordinary proxy forwarding path (TCP CONNECT and, for QUIC/UDP
    protocols, the same tunnel that carries UDP)."""
    tag = ob.get("tag", "candidate")
    listen_port = None
    tmp_path = None
    proc = None
    started = time.monotonic()
    last_error = "unknown error"
    try:
        listen_port = _pick_ephemeral_port()
        safe_tag = re.sub(r"[^A-Za-z0-9_.-]", "_", str(tag))[:80] or "candidate"
        tmp_path = f"{CONFIG_PATH}.fvone.{os.getpid()}.{listen_port}.json"
        config = {
            "log": {"level": "fatal"},
            "inbounds": [{
                "type": "mixed",
                "tag": "test-in",
                "listen": "127.0.0.1",
                "listen_port": listen_port,
            }],
            "outbounds": [ob, {"type": "direct", "tag": "direct"}],  # WireGuard -> endpoints below
            "route": {"final": tag, "default_domain_resolver": "dns-direct"},
            # Same requirement as the main connection config: sing-box 1.12+
            # exits immediately with no domain resolver declared, which
            # made every single candidate (S1-S8 and FV alike) fail this
            # check regardless of whether the server itself was reachable.
            "dns": {
                "servers": [{"type": "https", "tag": "dns-direct", "server": "1.1.1.1"}],
                "final": "dns-direct",
                "strategy": "prefer_ipv4",
            },
        }
        apply_endpoints(config)
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)

        # Validate exactly this candidate with the installed sing-box first.
        cp = subprocess.run(
            [binary, "check", "-c", tmp_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=12,
        )
        if cp.returncode != 0:
            return False, None, (cp.stdout or "sing-box check failed").strip()[-220:]

        proc = subprocess.Popen(
            [binary, "run", "-c", tmp_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        _FV_TEST_PROCS.add(proc)

        # Wait until the local HTTP proxy is actually accepting connections.
        ready = False
        deadline = time.monotonic() + 4.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                err = ""
                try:
                    err = proc.stderr.read().decode(errors="replace")[-220:]
                except Exception:
                    pass
                return False, None, (err or f"sing-box exited ({proc.returncode})").strip()
            try:
                with socket.create_connection(("127.0.0.1", listen_port), timeout=0.25):
                    ready = True
                    break
            except OSError:
                time.sleep(0.08)
        if not ready:
            return False, None, "local mixed proxy did not start"

        urls = test_urls or [
            "https://www.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
            "https://www.google.com/generate_204",
        ]
        proxy = f"http://127.0.0.1:{listen_port}"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
        for test_url in urls:
            try:
                t0 = time.monotonic()
                req = urllib.request.Request(
                    test_url,
                    headers={"User-Agent": "RaminVPN-FV-Verify/1.0", "Cache-Control": "no-cache"},
                )
                with opener.open(req, timeout=VERIFY_TIMEOUT_MS / 1000.0) as resp:
                    # Any HTTP response proves that the request crossed the
                    # candidate tunnel.  204 is ideal, but 200/3xx/4xx also
                    # prove connectivity; urllib follows redirects by default.
                    _ = resp.status
                delay = (time.monotonic() - t0) * 1000.0
            except Exception as e:
                last_error = str(e)
                continue
            # Country search: the REAL exit country (asked through this very
            # tunnel) must match, otherwise the candidate is useless.
            if want_country:
                cc = _fv_exit_country(opener)
                if metrics is not None:
                    metrics["country"] = cc
                if cc != want_country:
                    return False, None, f"exit country {cc}"
            # SW "udp" search: the candidate must ACTUALLY relay UDP (a real SOCKS5 UDP
            # ASSOCIATE + DNS round trip through this very tunnel), not just guess from
            # its protocol type - a vless/vmess/trojan/ss server may or may not really do it.
            if want_udp and not _socks5_udp_probe(listen_port):
                return False, None, "no UDP relay"
            # Quick probe passed. In quality mode the candidate must now also
            # prove it is stable / fast enough, reusing this same sing-box.
            if quality:
                return _fv_quality_gate(opener, delay, metrics, level=quality)
            return True, delay, None
        return False, None, last_error
    except Exception as e:
        return False, None, str(e)
    finally:
        if proc is not None:
            _FV_TEST_PROCS.discard(proc)
            try:
                proc.terminate()
                proc.wait(timeout=1.5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if tmp_path:
            try:
                os.remove(tmp_path)
            except Exception:
                pass


class FreeWaitDisplay:
    """A fixed two-row FV/SubLink progress display.

    Row 1: animated ``Please wait X/10 [bar] NN%``.
    Row 2: fixed ``Loading...``.

    The cursor always remains on row 2. Every redraw goes up exactly one
    terminal row, rewrites row 1, then returns to row 2 and rewrites it. No
    newline is emitted during animation, so the display cannot drift down or
    create a stack of Loading/progress lines in Termux.
    """
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    BAR_MAX = 24
    BAR_MIN = 6

    def __init__(self, total=10, progress_total=50):
        self.total = max(1, int(total))
        self.count = 0
        self.progress_total = max(1, int(progress_total))
        self.progress_done = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def set_progress_total(self, n):
        with self._lock:
            self.progress_total = max(1, int(n))
            self.progress_done = 0

    def tick(self, n=1):
        with self._lock:
            self.progress_done = min(self.progress_done + int(n), self.progress_total)

    def add_success(self):
        with self._lock:
            self.count = min(self.count + 1, self.total)

    def set_count(self, n):
        with self._lock:
            self.count = min(int(n), self.total)

    @staticmethod
    def _plain_width(s: str) -> int:
        return _visible_len(s)

    def _line(self, frame):
        with self._lock:
            n = self.count
            done = self.progress_done
            total = self.progress_total

        pct = int(done * 100 / total)
        width = max(term_width(), 20)

        # Spinner + text + brackets + percentage. Calculate the bar from the
        # actual visible width so the first row can never wrap in Termux.
        prefix_plain = f"{frame} Please wait {n}/{self.total} ["
        suffix_plain = f"] {pct:3d}%"
        fixed = self._plain_width(prefix_plain) + self._plain_width(suffix_plain)
        bar_width = min(self.BAR_MAX, max(self.BAR_MIN, width - fixed - 1))
        if fixed + bar_width > width - 1:
            bar_width = max(1, width - fixed - 1)

        filled = int(bar_width * done / total)
        bar = "█" * filled + "░" * (bar_width - filled)
        line = (
            f"{frame} Please wait {n}/{self.total} "
            f"[{_C.CYAN}{bar}{_C.RESET}] {pct:3d}%"
        )
        # The width calculation above guarantees no wrap; don't use a normal
        # len()-based truncation here because ANSI escape sequences are not
        # terminal columns.
        return line

    def _draw(self, frame):
        # Cursor is always on row 2 (Loading...). Move to row 1, replace the
        # entire row, move back to row 2, replace the entire row. The cursor
        # ends exactly where it started; no scrolling occurs.
        line = self._line(frame)
        sys.stdout.write(
            "\x1b[1A" + CLEAR_LINE + line +
            "\x1b[1B" + CLEAR_LINE + "Loading..."
        )
        sys.stdout.flush()

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            frame = f"{_C.CYAN}{self.FRAMES[i % len(self.FRAMES)]}{_C.RESET}"
            self._draw(frame)
            i += 1
            time.sleep(0.08)

    def start(self):
        frame = f"{_C.CYAN}{self.FRAMES[0]}{_C.RESET}"
        # Exactly two physical terminal rows are created once.
        sys.stdout.write(CLEAR_LINE + self._line(frame) + "\n" + CLEAR_LINE + "Loading...")
        sys.stdout.flush()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def stop(self, final_count=None, clear=True):
        if final_count is not None:
            self.set_count(final_count)
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        if clear:
            # Cursor is on row 2. Clear row 2, move to row 1 and clear it,
            # then return to row 2. No extra blank/new line is introduced.
            sys.stdout.write(
                CLEAR_LINE + "\x1b[1A" + CLEAR_LINE + "\x1b[1B\r"
            )
        else:
            frame = f"{_C.CYAN}{self.FRAMES[0]}{_C.RESET}"
            sys.stdout.write(
                "\x1b[1A" + CLEAR_LINE + self._line(frame) +
                "\x1b[1B" + CLEAR_LINE + "Loading..."
            )
        sys.stdout.flush()


def _verify_fv_sublink_isolated(binary: str, pool: list, top_n: int, label="Verify", test_urls=None, wait_display=None, quality: int = 0,
                                stop_after: int = None, deadline: float = None):
    """Verify FV/SubLink candidates independently.

    When wait_display is supplied, this function updates that ONE display and
    never creates a ProgressBar of its own. This is what keeps FV and SS from
    producing a stack of FV_WAIT progress rows.

    stop_after: once this many candidates have passed, candidates that have not
    started yet are skipped (ones already running still finish).
    deadline: time.monotonic() value after which unstarted candidates are skipped.
    """
    if not pool:
        return []
    results = []
    failures = []
    stop_evt = threading.Event()
    succ_lock = threading.Lock()
    succ_count = [0]
    max_workers = min(8, len(pool))
    own_wait = wait_display is None and label == "FV_WAIT"
    fv_wait = wait_display or (FreeWaitDisplay(top_n, len(pool)).start() if own_wait else None)
    pb = None if fv_wait else ProgressBar(label, total=len(pool))
    cm = contextlib.nullcontext() if fv_wait else pb
    with cm as progress:
        def worker(item):
            ob, _old_delay = item
            if stop_evt.is_set() or (deadline is not None and time.monotonic() > deadline):
                if fv_wait:
                    fv_wait.tick(1)
                else:
                    progress.tick()
                return ob, False, None, "skipped"
            ok, delay_ms, err = _verify_one_fv_sublink(binary, ob, test_urls, quality=quality)
            if ok and delay_ms is not None and stop_after:
                with succ_lock:
                    succ_count[0] += 1
                    if succ_count[0] >= stop_after:
                        stop_evt.set()
            if fv_wait:
                fv_wait.tick(1)
                if ok and delay_ms is not None:
                    fv_wait.add_success()
            else:
                progress.tick()
            return ob, ok, delay_ms, err
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(worker, item) for item in pool]
            for fut in concurrent.futures.as_completed(futures):
                ob, ok, delay_ms, err = fut.result()
                if ok and delay_ms is not None:
                    results.append((ob, delay_ms / 1000.0))
                elif len(failures) < 5 and err != "skipped":
                    failures.append((ob.get("tag", "?"), err or "connectivity test failed"))
    results.sort(key=lambda x: x[1])
    if own_wait and fv_wait:
        fv_wait.stop(len(results))
    # FV/SS intentionally stays quiet while scanning. For ordinary internal
    # verification calls, keep the old diagnostic output.
    if not fv_wait and not results and failures:
        print(f"{WARN} {label}: sample failure reasons:")
        for tag, err in failures[:5]:
            print(f"  {_C.DIM}{tag}: {err}{_C.RESET}")
    return results[:top_n] if top_n else results


def verify_candidates_real(binary: str, ranked: list, top_n: int, label: str = "Verify", max_candidates: int = None, test_urls: list = None) -> list:
    """End-to-end verification for every protocol.

    Every candidate is tested in its own temporary sing-box process with a
    real mixed-proxy HTTP request. This avoids the old all-in-one Clash API
    test path, which could make a whole S1-S8 batch look dead when one
    outbound/config was invalid or when the API delay probe was unreliable.
    The same path is now used for built-in S1-S8, FV and SubLink, so protocol
    support is tested by the actual sing-box data path rather than a raw TCP
    probe.
    """
    pool = ranked[:VERIFY_MAX_CANDIDATES] if max_candidates is None else ranked[:max_candidates]
    if not pool:
        return []
    return _verify_fv_sublink_isolated(
        binary, pool, top_n, label=label,
        test_urls=test_urls or [
            "https://www.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
            "https://www.google.com/generate_204",
        ]
    )


def prompt_server_choice(top: list) -> str:
    """Asks the person to pick a server number. Returns the chosen outbound's
    tag, or None to keep using sing-box's automatic best-server selection."""
    print(f"[?] Enter a number (1-{len(top)}) to pick a server, "
          f"or press Enter for automatic selection: ", end="", flush=True)
    try:
        raw = input_queue.get()
    except Exception:
        return None

    raw = (raw or "").strip()
    if not raw:
        return None

    try:
        idx = int(raw)
        if 1 <= idx <= len(top):
            return top[idx - 1][0]["tag"]
    except ValueError:
        pass

    print("[93m⚠[0m Invalid choice - using automatic selection instead.")
    return None


def geolocate_one_https(address: str):
    """Fallback per-IP HTTPS lookup (ipwho.is) - used when the direct HTTP
    batch lookup can't be reached (e.g. blocked before the tunnel is up)."""
    try:
        req = urllib.request.Request(f"https://ipwho.is/{urllib.parse.quote(address)}")
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode())
        if data.get("success", True):
            conn = data.get("connection") or {}
            return {
                "country": data.get("country", "?"),
                "city": data.get("city", "?"),
                "isp": conn.get("isp", "?"),
                "org": conn.get("org", "?"),
            }
    except Exception:
        pass
    return None


def geolocate_servers(top: list) -> dict:
    """Batch geo-lookup (direct, no proxy - the tunnel isn't up yet) for the
    server address of each candidate. Returns {tag: {country, city, isp, org}}.
    Tries a fast HTTP batch lookup first, then falls back to per-IP HTTPS
    lookups (some networks block plain HTTP to the batch endpoint)."""
    queries = [{"query": ob["server"]} for ob, _ in top]
    try:
        req = urllib.request.Request(
            "http://ip-api.com/batch?fields=status,country,city,isp,org,query",
            data=json.dumps(queries).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            results = json.loads(resp.read().decode())
        geo_by_tag = {}
        for (ob, _), info in zip(top, results):
            if info.get("status") == "success":
                geo_by_tag[ob["tag"]] = {
                    "country": info.get("country", "?"),
                    "city": info.get("city", "?"),
                    "isp": info.get("isp", "?"),
                    "org": info.get("org", "?"),
                }
        if geo_by_tag:
            return geo_by_tag
    except Exception:
        pass

    print_transient(f"{WARN} Direct batch lookup failed - retrying one-by-one over HTTPS...")
    geo_by_tag = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ob = {
            executor.submit(geolocate_one_https, ob["server"]): ob for ob, _ in top
        }
        for future in concurrent.futures.as_completed(future_to_ob):
            ob = future_to_ob[future]
            info = future.result()
            if info:
                geo_by_tag[ob["tag"]] = info
    return geo_by_tag


def geo_is_complete(geo: dict) -> bool:
    """A server only counts as having 'known' location info if country,
    city, ISP AND org all actually resolved to a real value."""
    if not geo:
        return False
    return all(geo.get(k) not in (None, "", "?") for k in ("country", "city", "isp", "org"))


def print_selection_table(top: list):
    """Compact grid of '#  Type-ping' cells, as many columns as fit the
    terminal width. No server name, location, ISP, or Org - those either
    wrapped every row onto two lines on a phone-width terminal, or (for
    the old ISP/Org list) printed one line per candidate, up to 50 lines
    of near-identical 'Cloudflare, Inc.' text. This just shows enough to
    compare the top candidates at a glance before #1 auto-connects."""
    entries = []
    for i, (ob, latency) in enumerate(top, 1):
        proto = {
            "vless": "Vless", "trojan": "Trojan", "vmess": "VMess",
            "shadowsocks": "SS", "hysteria": "Hysteria", "hysteria2": "Hysteria2",
            "tuic": "TUIC", "wireguard": "WireGuard", "shadowtls": "ShadowTLS",
            "anytls": "AnyTLS", "naive": "Naive", "ssh": "SSH", "snell": "Snell",
            "socks": "SOCKS", "http": "HTTP",
        }.get(ob.get("type"), (ob.get("type") or "?").capitalize())
        entries.append(f"{i:>2}.{proto}-{latency * 1000:.0f}ms")

    if not entries:
        return

    width = max(term_width() - 1, 1)
    cell_width = max(len(e) for e in entries) + 2
    cols = max(1, width // cell_width)

    print()
    for row_start in range(0, len(entries), cols):
        row = entries[row_start:row_start + cols]
        print("".join(e.ljust(cell_width) for e in row))
    print()




# ---- Live stdin commands (type 'r' + Enter anytime to force a rescan) ------
input_queue = queue.Queue()
_STDIN_CLOSED = threading.Event()  # set when stdin reached EOF (no more input will ever arrive)


def _stdin_reader():
    try:
        for line in sys.stdin:
            input_queue.put(line.strip())
    except Exception:
        pass
    finally:
        _STDIN_CLOSED.set()


def start_stdin_reader():
    threading.Thread(target=_stdin_reader, daemon=True).start()


def _drain_stale_input_queue() -> int:
    """Discards any input lines already sitting in input_queue. Needed right
    after a single-line prompt like 'Paste Link:' consumes just the first
    line: if the user's clipboard paste actually contained more than one
    line (a multi-line block copied by mistake, a trailing blank line, a
    link with an embedded newline from some apps), the stdin reader thread
    has already queued every extra line by the time we resume. Left alone,
    each of those fragments gets replayed on later loop iterations as a
    bogus top-level command; being unrecognized, every one of them redraws
    the input prompt IN PLACE (no full clear), which stacks up duplicate
    'Type + Enter :' lines and corrupts everything above them (DNS/Sub
    Links list, banner). Returns how many stray lines were discarded."""
    discarded = 0
    while True:
        try:
            input_queue.get_nowait()
            discarded += 1
        except queue.Empty:
            break
    return discarded


def probe_bindable_ports(ports: list, host: str = "127.0.0.1", retries: int = 2,
                          retry_delay: float = 0.3, verbose: bool = False) -> list:
    """Test-binds each port and keeps only the ones that actually succeed.
    Filters out privileged ports (<1024, need root) and ports already taken
    by something else - a single unbindable port would otherwise crash
    sing-box entirely (it fails to start if ANY inbound can't bind).

    Retries each port a couple of times with a short delay before giving up
    on it - a port can look briefly busy right after a previous sing-box
    process was killed, even though it's actually free a moment later.
    With verbose=True, prints the specific reason each failed port was
    excluded (useful for diagnosing "every port failed" cases)."""
    good = []
    for port in ports:
        last_err = None
        for attempt in range(retries + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((host, port))
                good.append(port)
                last_err = None
                break
            except OSError as e:
                last_err = e
                if attempt < retries:
                    time.sleep(retry_delay)
        if last_err and verbose:
            print(f"{WARN} port {port} unavailable: {last_err}")
    return good


DNS_PROVIDERS = [
    ("Cloud", "1.1.1.1"),
    ("Google", "8.8.8.8"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
    ("AdGuard", "94.140.14.14"),
    ("Shecan", "178.22.122.100"),
    ("Mullvad", "194.242.2.2"),
    ("ControlD", "76.76.2.0"),
    ("Verisign", "64.6.64.6"),
    ("Comodo", "8.26.56.26"),
]
DNS_PROVIDER_SECONDARY_IPS = {
    # Second, independent IP of the same provider - included in Test All / ATU / ATT so a
    # provider isn't skipped just because its FIRST IP happens to be slow/blocked right now.
    # Never shown as its own D1-D10 entry; the winner still displays under the provider's
    # normal name, just with this IP instead ("Google (8.8.4.4) - UDP", for example).
    # Mullvad has no second IPv4 of its own, so it is not in this dict.
    "Cloud": "1.0.0.1",
    "Google": "8.8.4.4",
    "Quad9": "149.112.112.112",
    "OpenDNS": "208.67.220.220",
    "AdGuard": "94.140.15.15",
    "Shecan": "185.51.200.2",
    "ControlD": "76.76.10.0",
    "Verisign": "64.6.65.6",
    "Comodo": "8.20.247.20",
}
DNS_PROVIDER_COMMANDS = {f"d{i}": i - 1 for i in range(1, len(DNS_PROVIDERS) + 1)}  # "d1".."d8" -> index
DNS_OFF_COMMANDS = {"d", "dns"}  # turns tunnel DNS off entirely (system default)
DNS_ALL_TEST_COMMANDS = {"at", "alltest", "dnstest"}  # race every DNS provider (UDP + TCP) and pick the fastest working one
DNS_ALL_TEST_UDP_COMMANDS = {"atu"}   # same race, UDP:53 only
DNS_ALL_TEST_TCP_COMMANDS = {"att"}   # same race, TCP:53 only

SUB_COMMANDS = {f"s{i}": i - 1 for i in range(1, BUILTIN_SUB_COUNT + 1)}  # built-in S1..S8 only
LINK_COMMANDS = {f"l{i}": BUILTIN_SUB_COUNT + i - 1 for i in range(1, len(SUB_URLS) - BUILTIN_SUB_COUNT + 1)}  # custom Link 1..N
DNS_WINNER = None  # {"name", "ip", "latency_ms", "proto"} - the fastest
# DNS provider+transport combo that actually answered a real query THROUGH
# the tunnel, set once after the post-connect DNS race (races both UDP and
# TCP:53 per provider, since some servers - e.g. Cloudflare Workers - can
# only ever carry TCP). build_singbox_config() reads this to decide whether
# to route domain lookups through the tunnel (faster/more reliable than the
# default resolver) or leave the normal/system DNS; print_connection_info()
# reads it to show which provider+transport won. DNS_DISABLED, when True,
# forces plain system DNS regardless of DNS_WINNER - set by the 'd'/'dns'
# command, mirroring Fragment's off toggle.
DNS_DISABLED = True


def _build_dns_query(qname: str = "cloudflare.com.") -> bytes:
    """Minimal raw DNS query (A record, IN class)."""
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    labels = qname.strip(".").split(".")
    qname_bytes = b"".join(bytes([len(p)]) + p.encode() for p in labels) + b"\x00"
    question = qname_bytes + b"\x00\x01\x00\x01"  # QTYPE=A, QCLASS=IN
    return header + question


def test_dns_via_tunnel_udp(dest_ip: str, timeout: float = 4.0):
    """Sends a real DNS query to dest_ip over UDP THROUGH the tunnel, using
    the local mixed proxy's SOCKS5 UDP ASSOCIATE support (a proper UDP
    relay, not just a TCP:53 probe like the old check used). Returns the
    round-trip latency in milliseconds if it gets back a real, successful
    (RCODE 0) answer, or None on any failure/timeout - used to race every
    DNS_PROVIDERS entry against each other and keep only the fastest."""
    tcp_ctrl = None
    udp_sock = None
    try:
        start = time.monotonic()
        tcp_ctrl = socket.create_connection(("127.0.0.1", LOCAL_SOCKS_HTTP_PORT), timeout=timeout)
        tcp_ctrl.settimeout(timeout)
        tcp_ctrl.sendall(b"\x05\x01\x00")  # ver=5, 1 method, no-auth
        resp = tcp_ctrl.recv(2)
        if len(resp) != 2 or resp[0] != 0x05 or resp[1] != 0x00:
            return None
        # UDP ASSOCIATE - client's own UDP source addr/port aren't known yet,
        # so 0.0.0.0:0 is sent per RFC 1928; the reply's BND.ADDR/BND.PORT is
        # the relay address to actually send UDP datagrams to.
        tcp_ctrl.sendall(bytes([0x05, 0x03, 0x00, 0x01]) + socket.inet_aton("0.0.0.0") + (0).to_bytes(2, "big"))
        resp = tcp_ctrl.recv(10)
        if len(resp) < 10 or resp[1] != 0x00 or resp[3] != 0x01:
            return None  # only handle an IPv4 relay address (always the case for 127.0.0.1)
        bnd_addr = socket.inet_ntoa(resp[4:8])
        bnd_port = int.from_bytes(resp[8:10], "big")
        if bnd_addr == "0.0.0.0":
            bnd_addr = "127.0.0.1"  # "same address you used for the control connection"

        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.settimeout(timeout)
        query = _build_dns_query()
        # SOCKS5 UDP request header: RSV(2)=0, FRAG(1)=0, ATYP(1)=IPv4, DST.ADDR, DST.PORT
        udp_header = b"\x00\x00\x00\x01" + socket.inet_aton(dest_ip) + (53).to_bytes(2, "big")
        udp_sock.sendto(udp_header + query, (bnd_addr, bnd_port))
        data, _ = udp_sock.recvfrom(2048)

        if len(data) < 10 or data[3] != 0x01:
            return None  # same IPv4-only assumption for the reply's own header
        dns_resp = data[10:]
        if len(dns_resp) < 12:
            return None
        rcode = dns_resp[3] & 0x0F
        if rcode != 0:
            return None
        return (time.monotonic() - start) * 1000
    except Exception:
        return None
    finally:
        if udp_sock:
            udp_sock.close()
        if tcp_ctrl:
            tcp_ctrl.close()


def test_dns_via_tunnel_tcp(dest_ip: str, timeout: float = 4.0):
    """Sends a real DNS query to dest_ip over TCP:53 THROUGH the tunnel
    (plain SOCKS5 CONNECT, then DNS-over-TCP framing). Returns the
    round-trip latency in milliseconds on a real, successful (RCODE 0)
    answer, or None on any failure/timeout. Kept alongside the UDP
    version because some VLESS/Trojan servers - notably ones running
    behind Cloudflare Workers, which can only relay TCP/HTTP, never raw
    UDP - can NEVER carry UDP traffic no matter what, so without a TCP
    fallback the whole DNS race would always fail on those."""
    sock = None
    try:
        start = time.monotonic()
        sock = socket.create_connection(("127.0.0.1", LOCAL_SOCKS_HTTP_PORT), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")  # ver=5, 1 method, no-auth
        resp = sock.recv(2)
        if len(resp) != 2 or resp[0] != 0x05 or resp[1] != 0x00:
            return None
        req = bytes([0x05, 0x01, 0x00, 0x01]) + socket.inet_aton(dest_ip) + (53).to_bytes(2, "big")
        sock.sendall(req)
        resp = sock.recv(10)
        if len(resp) < 2 or resp[1] != 0x00:
            return None
        query = _build_dns_query()
        sock.sendall(len(query).to_bytes(2, "big") + query)  # DNS-over-TCP framing
        raw_len = sock.recv(2)
        if len(raw_len) != 2:
            return None
        resp_len = int.from_bytes(raw_len, "big")
        dns_resp = b""
        while len(dns_resp) < resp_len:
            chunk = sock.recv(resp_len - len(dns_resp))
            if not chunk:
                break
            dns_resp += chunk
        if len(dns_resp) < 12:
            return None
        rcode = dns_resp[3] & 0x0F
        if rcode != 0:
            return None
        return (time.monotonic() - start) * 1000
    except Exception:
        return None
    finally:
        if sock:
            sock.close()


def race_dns_results_via_tunnel(proto: str = None) -> list:
    """Races every DNS_PROVIDERS entry against each other concurrently -
    each one tried over BOTH UDP and TCP:53 at once (unless proto is set to
    "UDP" or "TCP", which races that transport only - ATU / ATT) - and
    returns EVERY (provider, transport) combination that answered correctly,
    fastest first, as a list of {"name", "ip", "latency_ms", "proto"} (empty
    when every attempt failed/timed out, meaning: keep the normal/system DNS
    instead). Racing both transports, not just UDP, matters because some
    VLESS/Trojan servers (e.g. ones running behind Cloudflare Workers) can
    only ever carry TCP - Workers have no way to relay raw UDP packets at
    all - so on those, every UDP attempt is guaranteed to fail regardless of
    which DNS provider or how good the network is, and only TCP can ever work.

    The full list (not just the winner) is what lets Auto Setting compare the
    DNS it is using right now with the best one, and only switch - which
    restarts the tunnel - when the gain is worth it.

    Each provider's SECOND IP (DNS_PROVIDER_SECONDARY_IPS) is raced too, under
    the same provider name, so a provider isn't skipped just because its
    first IP alone is slow or blocked on this network."""
    results = []
    jobs = []
    for name, ip in DNS_PROVIDERS:
        ips = [ip]
        second = DNS_PROVIDER_SECONDARY_IPS.get(name)
        if second:
            ips.append(second)
        for one_ip in ips:
            if proto is None or proto == "UDP":
                jobs.append((name, one_ip, "UDP", test_dns_via_tunnel_udp))
            if proto is None or proto == "TCP":
                jobs.append((name, one_ip, "TCP", test_dns_via_tunnel_tcp))
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as executor:
        future_to_job = {executor.submit(fn, ip): (name, ip, proto) for name, ip, proto, fn in jobs}
        for future in concurrent.futures.as_completed(future_to_job):
            name, ip, proto = future_to_job[future]
            latency = future.result()
            if latency is not None:
                results.append({"name": name, "ip": ip, "latency_ms": latency, "proto": proto})
    results.sort(key=lambda r: r["latency_ms"])
    return results


def race_dns_via_tunnel(proto: str = None) -> dict:
    """The single fastest working DNS as {"name", "ip", "latency_ms", "proto"},
    or None if every provider failed (on the requested transport, or on both
    when proto is None - see race_dns_results_via_tunnel for how the race works)."""
    results = race_dns_results_via_tunnel(proto=proto)
    return results[0] if results else None


def pick_dns_via_tunnel(start_index: int = 0) -> dict:
    """Tries DNS_PROVIDERS in order starting at start_index and wrapping
    around, racing each provider's own UDP and TCP:53 attempts against
    each other (like race_dns_via_tunnel does per-provider) and moving on
    to the NEXT provider only if that one fails on both transports. Used
    for a manually-picked provider (D1-D6): if the person's choice
    doesn't actually work, the next one is tried automatically instead of
    just failing outright. Returns the winning {"name","ip","latency_ms",
    "proto"} dict, or None if every provider failed."""
    n = len(DNS_PROVIDERS)
    for i in range(n):
        name, ip = DNS_PROVIDERS[(start_index + i) % n]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            fut_udp = executor.submit(test_dns_via_tunnel_udp, ip)
            fut_tcp = executor.submit(test_dns_via_tunnel_tcp, ip)
            udp_latency, tcp_latency = fut_udp.result(), fut_tcp.result()
        candidates = []
        if udp_latency is not None:
            candidates.append({"name": name, "ip": ip, "latency_ms": udp_latency, "proto": "UDP"})
        if tcp_latency is not None:
            candidates.append({"name": name, "ip": ip, "latency_ms": tcp_latency, "proto": "TCP"})
        if candidates:
            return min(candidates, key=lambda c: c["latency_ms"])
    return None


def _build_speed_boost_outbounds(outbounds: list) -> list:
    """Return runtime copies of VLESS/Trojan outbounds with speed tuning.

    The original parsed outbounds are intentionally left untouched: the server
    discovery/verification pipeline should test the plain configs, while the
    live connection gets the optional tuning only when B/Speed Boost is ON.

    TCP Fast Open and TCP Multi Path are Dial Fields. Multiplex is added only
    to plain VLESS/Trojan transports (no V2Ray transport such as WebSocket),
    which is the conservative choice because multiplex requires compatible
    server-side support and a transport layer can have its own constraints.
    """
    tuned = []
    for original in outbounds:
        ob = dict(original)
        if ob.get("type") in {"vless", "trojan"}:
            ob["tcp_fast_open"] = True
            ob["tcp_multi_path"] = True

            # Avoid stacking multiplex on top of WS/other V2Ray transports.
            # Plain VLESS/Trojan can use sing-box's outbound multiplex support.
            if "transport" not in ob:
                ob["multiplex"] = {
                    "enabled": True,
                    "protocol": "smux",
                    "max_connections": SPEED_BOOST_MAX_CONNECTIONS,
                    "min_streams": SPEED_BOOST_MIN_STREAMS,
                }
        tuned.append(ob)
    return tuned

def _build_speed_boost2_outbounds(outbounds: list) -> list:
    """More aggressive Speed Boost 2 runtime tuning.

    Keeps the proven Boost-1 optimizations, raises the multiplex connection
    ceiling, and uses shorter TCP keepalive/connection timers. It stays
    conservative around WebSocket and other explicit V2Ray transports.
    """
    tuned = []
    for original in outbounds:
        ob = dict(original)
        if ob.get("type") in {"vless", "trojan"}:
            ob["tcp_fast_open"] = True
            ob["tcp_multi_path"] = True
            ob["tcp_keep_alive"] = "30s"
            ob["tcp_keep_alive_interval"] = "15s"
            ob["connect_timeout"] = "8s"

            if "transport" not in ob:
                ob["multiplex"] = {
                    "enabled": True,
                    "protocol": "smux",
                    "max_connections": SPEED_BOOST2_MAX_CONNECTIONS,
                }
        tuned.append(ob)
    return tuned


def build_singbox_config(outbounds: list, enable_ir_bypass: bool = False,
                          manual_tag: str = None, enable_fragment: int = None) -> dict:
    """Build the live sing-box config.

    enable_fragment, when set, is the id (1-4) of the FRAGMENT_PRESETS entry
    to apply - not just True/False - so different DPI-evasion profiles can be
    tried live without restarting the script. Speed Boost is likewise applied
    only to the live config when SPEED_BOOST_ENABLED is True.
    """
    # Speed Boost is applied only to the live sing-box config. Keeping the
    # caller's list untouched means server ranking/verification remains fair.
    if SPEED_BOOST2_ENABLED:
        runtime_outbounds = _build_speed_boost2_outbounds(outbounds)
    elif SPEED_BOOST_ENABLED:
        runtime_outbounds = _build_speed_boost_outbounds(outbounds)
    else:
        runtime_outbounds = [dict(o) for o in outbounds]
    tags = [o["tag"] for o in runtime_outbounds]

    inbounds = [
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": LOCAL_SOCKS_HTTP_PORT,
        },
    ]

    # extra ports - same routing as the main port, just additional listeners
    for i, extra_port in enumerate(EXTRA_PORTS):
        inbounds.append(
            {
                "type": "mixed",
                "tag": f"mixed-in-extra-{i}",
                "listen": "127.0.0.1",
                "listen_port": extra_port,
            }
        )

    route_rules = []

    if enable_fragment and enable_fragment in FRAGMENT_PRESETS:
        # Non-final route-options rule action (sing-box 1.13.0+): only sets
        # dial options for connections sing-box makes itself (including our
        # own VLESS/Trojan outbound's TLS handshake to its server) - it
        # does NOT pick an outbound, so it can't conflict with the
        # "route"/"direct" rules below. No match conditions = applies to
        # every connection. This must NOT be a field inside any outbound's
        # own "tls" object - that was tried once before and made sing-box
        # refuse to start at all.
        route_rules.append(fragment_route_rule(enable_fragment))

    # ChatGPT/OpenAI must stay INSIDE the active tunnel. The previous build
    # incorrectly sent these domains to "direct", which defeats the VPN when
    # the local ISP blocks or interferes with OpenAI. OpenAI's current network
    # guidance lists these domains and also requires WebSocket traffic to
    # chatgpt.com on TCP/443 for some features. The first rule therefore sends
    # all known OpenAI/ChatGPT hostnames to the active server group (manual
    # server when selected, otherwise urltest/auto), before any Iran-direct
    # bypass rule can match.
    route_rules.append({"action": "sniff", "timeout": "300ms"})
    openai_domains = [
        "auth.openai.com", "chatgpt.com", "chat.openai.com",
        "android.chat.openai.com", "ios.chat.openai.com",
        "desktop.chat.openai.com", "ws.chatgpt.com",
        "openai.com", "oaiusercontent.com", "oaistatic.com",
        "oaistatsig.com", "ct.sendgrid.net", "auth0.openai.com",
        "tcr9i.chat.openai.com", "cdn.openaimerge.com",
        "challenges.cloudflare.com",
    ]
    chatgpt_outbound = manual_tag or "auto"
    route_rules.append({
        "domain_suffix": openai_domains,
        "action": "route",
        "outbound": chatgpt_outbound,
    })
    # ChatGPT Voice currently uses UDP/3478. When an application sends that
    # traffic through this local SOCKS5/HTTP entry point, keep it in the same
    # tunnel as the web/app traffic.
    route_rules.append({
        "network": "udp", "port": 3478, "action": "route", "outbound": chatgpt_outbound,
    })
    rule_sets = []

    if enable_ir_bypass:
        # Iranian sites/IPs go direct (bypass the VPN) - faster + doesn't waste
        # tunnel bandwidth. Uses LOCAL copies of the rule-sets (already downloaded
        # once through the tunnel) so sing-box never has to fetch them live at
        # startup - that caused a startup deadlock/timeout before.
        route_rules.append({"rule_set": ["geosite-ir", "geoip-ir"], "action": "route", "outbound": "direct"})
        rule_sets = [
            {"tag": "geosite-ir", "type": "local", "format": "binary", "path": GEOSITE_IR_PATH},
            {"tag": "geoip-ir", "type": "local", "format": "binary", "path": GEOIP_IR_PATH},
        ]

    # a separate port for each of the top N servers - only when explicitly enabled
    if ENABLE_PER_SERVER_PORTS:
        for i, tag in enumerate(tags):
            in_tag = f"direct-in-{i}"
            inbounds.append(
                {
                    "type": "mixed",
                    "tag": in_tag,
                    "listen": "127.0.0.1",
                    "listen_port": PER_SERVER_BASE_PORT + i,
                }
            )
            route_rules.append({"inbound": [in_tag], "action": "route", "outbound": tag})

    # sing-box 1.12+ refuses to start at all without a domain resolver
    # declared somewhere (route.default_domain_resolver or per-outbound) -
    # "dns-direct" is always present so that requirement is always met,
    # independent of whether the optional tunnel-DNS-racing feature below
    # found any working provider (a prior version of this script only
    # defined a "dns" section when tunnel DNS worked, which meant sing-box
    # hard-crashed with a FATAL as soon as it didn't - making every single
    # server look "dead" even though none of them actually were).
    # No "detour" here on purpose: sing-box treats detouring a DNS server
    # to a plain, unconfigured "direct" outbound as redundant/invalid
    # ("detour to an empty direct outbound makes no sense") and refuses to
    # start - omitting detour entirely already dials directly by default,
    # which is exactly what we want for this one.
    # DoH (not plain UDP) on purpose: this resolver bootstraps BEFORE the
    # tunnel exists, so a plain-UDP query would expose every resolved domain
    # to the ISP in cleartext. HTTPS encrypts it - the ISP only sees a
    # connection to 1.1.1.1, not what's being asked. ("detour" intentionally
    # omitted - same reason as described above this block.)
    dns_servers = [{"type": "https", "tag": "dns-direct", "server": "1.1.1.1"}]
    dns_final = "dns-direct"
    if DNS_WINNER and not DNS_DISABLED:
        detour = manual_tag or "auto"  # follows whichever outbound is active/final
        dns_servers.append({
            "type": DNS_WINNER["proto"].lower(), "tag": "dns-tunnel",
            "server": DNS_WINNER["ip"], "detour": detour,
        })
        dns_final = "dns-tunnel"
    dns_section = {
        "servers": dns_servers,
        "final": dns_final,
        "strategy": "prefer_ipv4",
        # sing-box 1.14 DNS options. The cache always keys by transport now
        # (independent_cache is deprecated and must NOT be set).
        "cache_capacity": 4096,
        # Optimistic cache: an expired answer is returned immediately while it
        # is refreshed in the background - much lower latency on slow/lossy
        # links. Stale answers are served for at most 6 hours (default 3 days).
        "optimistic": {"enabled": True, "timeout": "6h"},
        "timeout": "8s",  # per-query timeout (default 10s)
    }

    config = {
        "log": {"level": "fatal", "timestamp": True},
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{CLASH_API_PORT}",
            }
        },
        "inbounds": inbounds,
        "outbounds": runtime_outbounds
        + [
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": tags,
                "url": URLTEST_URL,
                "interval": URLTEST_INTERVAL,
                "idle_timeout": URLTEST_INTERVAL,
                "tolerance": URLTEST_TOLERANCE,
            },
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": route_rules,
            "rule_set": rule_sets,
            "final": manual_tag or "auto",
            "default_domain_resolver": "dns-direct",
        },
        "dns": dns_section,
    }
    # WireGuard/WARP: the legacy outbound no longer exists (sing-box >= 1.13),
    # so move those records into the top-level "endpoints" list. Endpoints are
    # referenced by tag exactly like outbounds (urltest "auto", route final,
    # DNS detour), and one WireGuard endpoint carries TCP and UDP together.
    return apply_endpoints(config)


def download_rulesets_via_proxy() -> bool:
    """Downloads the Iran geosite/geoip rule-sets THROUGH the now-active local
    proxy and caches them on disk. Returns True if both files are ready
    (freshly downloaded or already cached from a previous run)."""
    if os.path.exists(GEOSITE_IR_PATH) and os.path.exists(GEOIP_IR_PATH):
        return True

    proxy_url = f"http://127.0.0.1:{LOCAL_SOCKS_HTTP_PORT}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    )

    for url, path in ((GEOSITE_IR_URL, GEOSITE_IR_PATH), (GEOIP_IR_URL, GEOIP_IR_PATH)):
        if os.path.exists(path):
            continue
        try:
            with Spinner(f"Downloading {os.path.basename(path)}..."):
                with opener.open(url, timeout=20) as resp:
                    data = resp.read()
                tmp_path = path + ".tmp"
                with open(tmp_path, "wb") as f:
                    f.write(data)
                os.replace(tmp_path, path)
        except Exception as e:
            print(f"{WARN} Could not download {os.path.basename(path)}: {e}")
            return False

    return True


def load_vless_cache() -> dict:
    """{subscription_url: [vless_line, ...]} from the last successful fetch."""
    try:
        with open(VLESS_CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_vless_cache(cache: dict):
    try:
        with open(VLESS_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def fetch_all_outbounds(step_label: str = None, sub_indices: list = None, extended_parser: bool = False):
    """Always tries to update every subscription first and saves whatever it
    gets. If a subscription can't be updated for any reason (filtered
    domain, timeout, empty response, etc.), it falls back to the servers
    saved from the last successful update of that same subscription.
    step_label, if given (e.g. "Fetch 2/10"), is used as the visible
    prefix for the per-subscription status line instead of a generic
    "Fetching subscription i/N..." message.
    sub_indices, if given, restricts fetching to just those 0-based
    indices into SUB_URLS (e.g. the single subscription picked by
    pick_next_sub_index()) instead of all of them - each server's tag is
    still prefixed with its REAL SUB_URLS position (S{sub_i}-), never a
    renumbered one, so get_subscription_url_for_tag() keeps working."""
    indices = sub_indices if sub_indices is not None else list(range(len(SUB_URLS)))
    all_outbounds = []
    cache = load_vless_cache()
    cache_changed = False

    for pos, sub_i0 in enumerate(indices, 1):
        sub_i = sub_i0 + 1  # 1-based - matches SUB_URLS indexing and the S{sub_i}- tag prefix
        url = SUB_URLS[sub_i0]
        lines = []
        prefix = f"{step_label}: " if step_label else "Fetching "
        try:
            with Spinner(f"{prefix}subscription {pos}/{len(indices)}..."):
                if url.startswith("http://") or url.startswith("https://"):
                    _p = _state.get("proc")
                    _alive = _p is not None and _p.poll() is None
                    raw = ""
                    for via_proxy in ([True, False] if _alive else [False, True]):
                        try:
                            raw = fetch_subscription(url, via_proxy=via_proxy)
                            if raw:
                                break
                        except Exception:
                            continue
                else:
                    # a raw proxy:// link pasted directly via 'SL', not an HTTP
                    # subscription endpoint - use it as-is, no fetch needed.
                    raw = url
                lines = [l.strip() for l in raw.splitlines() if l.strip()]
                if not lines:
                    raise ValueError("subscription returned no servers")
            cache[url] = lines
            cache_changed = True
        except Exception as e:
            print(f"{WARN} Fetching subscription {sub_i} failed: {e}")
            cached_lines = cache.get(url) or []
            if cached_lines:
                print(f"    -> Using {len(cached_lines)} previously saved servers instead.")
                lines = cached_lines
            else:
                print("    -> No previously saved servers available for this subscription yet.")

        for i, line in enumerate(lines, 1):
            ob = parse_proxy_uri(line, i, extended=extended_parser)
            if ob:
                # prefix the tag with the subscription number so servers from
                # different subs never collide
                ob["tag"] = f"S{sub_i}-{ob['tag']}"
                all_outbounds.append(ob)

    if cache_changed:
        save_vless_cache(cache)

    if not all_outbounds:
        print(f"{WARN} No valid proxy servers found (supported mixed protocols) in any subscription.")
        return None

    return all_outbounds


def load_switch_server_cache() -> dict:
    try:
        with open(SWITCH_SERVER_CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_switch_server_pool(key: str, outbounds: list):
    if not key or not outbounds:
        return
    try:
        cache = load_switch_server_cache()
        cache[key] = outbounds[:FREE_VLESS_COUNT]
        with open(SWITCH_SERVER_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def load_switch_server_pool(key: str) -> list:
    try:
        ob = load_switch_server_cache().get(key, [])
        return ob if isinstance(ob, list) else []
    except Exception:
        return []


def switch_server_cache_key(free_mode=False, sub_index=None) -> str:
    if free_mode:
        return f"FV:{_state.get('free_source_index')}"
    if sub_index is None:
        return ""
    return f"SUB:{int(sub_index)}"


def load_free_vless_lines() -> list:
    try:
        with open(FREE_VLESS_CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_free_vless_lines(lines: list):
    try:
        with open(FREE_VLESS_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(lines, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def get_free_vless_source_name(source_index: int) -> str:
    try:
        i = int(source_index)
        if i < 0:  # sentinel (web/@channel search, never a real T<n>) - Python's
            raise IndexError  # negative indexing would otherwise silently return
        return FREE_VLESS_SOURCE_NAMES[i]  # the LAST real source's name (T29) instead.
    except Exception:
        return f"Free Source {int(source_index) + 1}"


def rebuild_free_pool_from_saved_lines(source_index: int):
    """Rebuild the last verified FV pool from free_vless_cache.json.

    This is a compatibility/repair path for Fast Connect sessions created by
    older versions which saved the working URI lines but did not persist the
    complete outbound pool inside fast_connect.json. It never tests or adds
    S1-S8.
    """
    try:
        source_index = int(source_index)
        source_code = get_free_vless_source_code(source_index)
        lines = load_free_vless_lines()
        pool = []
        seen = set()
        for i, line in enumerate(lines, 1):
            ob = parse_proxy_uri(line, i, extended=True)
            if not ob:
                continue
            ob["tag"] = f"FV-{source_code}-{ob['tag']}"
            if ob["tag"] not in seen:
                seen.add(ob["tag"])
                pool.append(ob)
            if len(pool) >= FREE_VLESS_COUNT:
                break
        return pool
    except Exception:
        return []


def get_free_vless_source_code(source_index: int) -> str:
    try:
        i = int(source_index)
        if i < 0:  # sentinel - see get_free_vless_source_name() above for why this
            raise IndexError  # must not fall through to FREE_VLESS_SOURCE_CODES[-1].
        return FREE_VLESS_SOURCE_CODES[i]
    except Exception:
        return f"F{int(source_index) + 1}"


def pick_next_free_source_index() -> int:
    """Pick the next Free Vless source in deterministic order.

    A fresh FV cycle starts at T1 and then walks every configured
    primary/fallback source. Source order is never randomized.
    """
    pool = _state.get("free_sub_pool") or []
    if not pool:
        pool = list(range(len(FREE_VLESS_SOURCES)))
    idx = pool.pop(0)
    _state["free_sub_pool"] = pool
    _state["free_source_index"] = idx
    return idx


def discover_free_vless(binary: str, source_index: int = None, verbose: bool = False,
                        ping_ceiling_ms: float = None):
    """Fetch one FV source and test usable configs in batches of 50.

    FV/SubLink use one shared, silent progress display. Source/repository
    names and intermediate failure messages are deliberately hidden from the
    user; only "Please wait X/10", the progress bar, and "Loading..." are
    shown during the scan. verbose=True (only the explicit T<n> command uses
    it) additionally prints exactly what each fetch attempt did, so a source
    that keeps coming back empty can be diagnosed instead of guessed at.
    """
    if source_index is None:
        source_index = pick_next_free_source_index()
    source_index = int(source_index) % len(FREE_VLESS_SOURCES)

    url = FREE_VLESS_SOURCES[source_index]
    source_code = get_free_vless_source_code(source_index)
    quality = _fv_quality_level_now()  # 0 = classic, 1/2 = quality gate (see FV_QUALITY_* above)
    target = FV_QUALITY_TARGET if quality else FREE_VLESS_MIN_WORKING
    wait = FreeWaitDisplay(FV_QUALITY_TARGET if quality else FREE_VLESS_COUNT, 50).start()
    source_deadline = (time.monotonic() + FV_SOURCE_TIME_BUDGET) if quality else None

    try:
        proc = _state.get("proc")
        alive = proc is not None and proc.poll() is None
        raw = ""
        dbg = []  # verbose notes - buffered, never printed while `wait`'s spinner
        # thread is running (that animates via raw cursor-movement escapes on a
        # background thread; printing at the same time corrupts the terminal), so
        # they're only flushed AFTER wait.stop() below, right before returning.
        for via_proxy in ([True, False] if alive else [False, True]):
            try:
                raw = fetch_subscription(url, via_proxy=via_proxy)
                dbg.append(f"  [debug] fetch via_proxy={via_proxy}: {len(raw)} chars")
                if raw:
                    break
            except Exception as e:
                dbg.append(f"  [debug] fetch via_proxy={via_proxy}: FAILED - {type(e).__name__}: {e}")
                continue
        if not raw:
            wait.stop(0)
            if verbose:
                for l in dbg:
                    print(l)
            return None, None

        full_lines, seen = [], set()
        for line in raw.splitlines():
            line = line.strip().lstrip("\ufeff")
            if not line or not line.startswith(SUPPORTED_PROXY_SCHEMES) or line in seen:
                continue
            seen.add(line)
            full_lines.append(line)

        if not full_lines:
            dbg.append(f"  [debug] got {len(raw)} chars but 0 supported proxy URIs in them")
            wait.stop(0)
            if verbose:
                for l in dbg:
                    print(l)
            return None, None

        if ping_ceiling_ms is not None:
            # The explicit T<n> command: save everything downloaded, BEFORE testing starts.
            # Always printed (not just buffered into `dbg`, which only surfaces on failure)
            # so the person can see the download happened before the test/connect begins.
            saved_path = _tsrc_save_file(source_index, get_free_vless_source_name(source_index), full_lines)
            if saved_path:
                print(f"{OK} {len(full_lines)} configs downloaded and saved -> {os.path.relpath(saved_path)}")

        parsed_pairs = []
        for i, line in enumerate(full_lines, 1):
            ob = parse_proxy_uri(line, i, extended=True)
            if ob:
                ob["tag"] = f"FV-{source_code}-{ob['tag']}"
                parsed_pairs.append((line, ob))

        if not parsed_pairs:
            wait.stop(0)
            if verbose:
                print(f"  [debug] {len(full_lines)} URI(s) found but none parsed into a usable config")
            return None, None

        line_by_tag = {ob["tag"]: line for line, ob in parsed_pairs}
        random.shuffle(parsed_pairs)
        batch_size = 50
        verified = []
        test_urls = [
            "https://www.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
        ]

        under_ceiling = 0   # how many of `verified` are within ping_ceiling_ms (T<n> only)

        for batch_start in range(0, len(parsed_pairs), batch_size):
            done = under_ceiling if ping_ceiling_ms is not None else len(verified)
            if done >= target:
                break
            if source_deadline is not None and time.monotonic() > source_deadline:
                break
            batch = parsed_pairs[batch_start:batch_start + batch_size]
            # The bar belongs to the current 50-config batch. This guarantees
            # it reaches 100% before that batch is considered complete.
            wait.set_progress_total(len(batch))
            ranked_batch = [(ob, 0.0) for _, ob in batch]
            batch_verified = _verify_fv_sublink_isolated(
                binary, ranked_batch, FREE_VLESS_COUNT,
                label="FV_WAIT",
                test_urls=test_urls, wait_display=wait,
                quality=quality,
                stop_after=(target - done) if quality else None,
                deadline=source_deadline,
            )
            verified.extend(batch_verified)
            verified.sort(key=lambda x: x[1])
            verified = verified[:FREE_VLESS_COUNT]
            if ping_ceiling_ms is not None:
                under_ceiling = sum(1 for _ob, ms in verified if ms is not None and ms <= ping_ceiling_ms)

            done = under_ceiling if ping_ceiling_ms is not None else len(verified)
            if done >= target:
                break

        # Quality mode: if the time budget ran out (or the source is small), a
        # couple of genuinely good nodes are still better than nothing.
        accept_min = min(target, FV_QUALITY_FALLBACK_MIN) if quality else target
        if len(verified) < accept_min:
            wait.stop(len(verified))
            return None, None

        top_with_latency = sorted(verified, key=lambda x: x[1])[:FREE_VLESS_COUNT]
        top_outbounds = [ob for ob, _ in top_with_latency]
        if not top_outbounds:
            wait.stop(0)
            return None, None

        manual_tag = top_outbounds[0]["tag"]
        if ping_ceiling_ms is not None:
            under = [ob for ob, ms in top_with_latency if ms is not None and ms <= ping_ceiling_ms]
            if under:
                manual_tag = under[0]["tag"]      # fastest candidate that meets the 800ms ask
            elif verbose:
                print(f"{WARN} No candidate answered under {ping_ceiling_ms:.0f} ms - "
                      f"connecting to the fastest one found ({top_with_latency[0][1]:.0f} ms) instead.")
        kept_lines = [line_by_tag[ob["tag"]] for ob in top_outbounds if ob["tag"] in line_by_tag]
        save_free_vless_lines(kept_lines)
        _state["free_source_index"] = source_index
        _state["free_verified_pool"] = top_outbounds[:FREE_VLESS_COUNT]
        save_switch_server_pool(switch_server_cache_key(True, source_index), top_outbounds)
        wait.stop(len(kept_lines))
        return top_outbounds, manual_tag
    except Exception:
        # Never leak an internal source/test exception into the progress UI.
        try:
            wait.stop(0)
        except Exception:
            pass
        return None, None

def _reset_free_vless_cycle(first_source_index: int = 0):
    first = int(first_source_index) % len(FREE_VLESS_SOURCES)
    _state["free_sub_pool"] = [i for i in range(len(FREE_VLESS_SOURCES)) if i != first]
    _state["free_source_index"] = first
    return first


def connect_free_vless_with_failover(binary: str, ir_bypass_enabled: bool = False,
                                    first_source_index: int = None, enable_fragment=None):
    """Discover AND connect a Free Vless source, advancing on any failure.
    This chain never falls back to S1-S8.

    Returns (proc, last_tag, ok, top_outbounds, manual_tag, source_index).
    """
    attempted = set()
    ordered_first = None
    _state["fv_quality_level"] = None  # every FV run starts at the strictest level
    if first_source_index is not None:
        ordered_first = _reset_free_vless_cycle(first_source_index)

    while len(attempted) < len(FREE_VLESS_SOURCES):
        if ordered_first is not None and ordered_first not in attempted:
            idx = ordered_first
            ordered_first = None
            pool = _state.get("free_sub_pool") or []
            if idx in pool:
                pool.remove(idx)
                _state["free_sub_pool"] = pool
        else:
            idx = pick_next_free_source_index()

        attempted.add(idx)
        _state["free_source_index"] = idx
        source_name = get_free_vless_source_name(idx)
        kill_singbox()
        _state["cleaned_up"] = False
        top_outbounds, manual_tag = discover_free_vless(binary, source_index=idx)
        if not top_outbounds:
            # Safety net: if the strictest level finds nothing in the first few
            # sources (very slow network, blocked test hosts...), drop the download
            # test for the remaining sources instead of never connecting.
            if (FV_QUALITY_MODE and len(attempted) >= FV_QUALITY_RELAX_AFTER
                    and _state.get("fv_quality_level") in (None, 2)):
                _state["fv_quality_level"] = 1
            continue

        kill_singbox()
        _state["cleaned_up"] = False
        # The connection screen is drawn INSIDE connect_with_fallback(), so the Free Vless
        # state must already be set: FV highlighted, "Switch Sub : T1 - Tn", "CONNECT to T<n>".
        _state["free_vless_mode"] = True
        _state["free_source_index"] = idx
        _state["free_verified_pool"] = top_outbounds[:FREE_VLESS_COUNT]
        proc, last_tag, ok = connect_with_fallback(
            binary, top_outbounds, manual_tag, ir_bypass_enabled, top_outbounds,
            label="Connected Free Vless", enable_fragment=enable_fragment
        )
        if last_tag and ok:
            _state["free_vless_mode"] = True
            _state["free_source_index"] = idx
            _state["free_verified_pool"] = top_outbounds[:FREE_VLESS_COUNT]
            save_switch_server_pool(switch_server_cache_key(True, idx), top_outbounds)
            return proc, last_tag, ok, top_outbounds, manual_tag, idx

        kill_singbox()
        _state["cleaned_up"] = False

    _state["free_vless_mode"] = False
    return None, None, False, None, None, None

# ============================================================================
# Free Vless RESERVE: silent background search, Switch Server numbers, failover
# ============================================================================
_RESERVE = None  # the ReserveManager instance (created in main())


def _ob_fingerprint(ob: dict) -> tuple:
    """Identity of a config independent of its display tag."""
    return (str(ob.get("type")), str(ob.get("server")), str(ob.get("server_port")),
            str(ob.get("uuid") or ob.get("password") or ob.get("username") or ""))


def _quiet_verify(binary: str, nodes: list, level: int = 0, stop_after: int = None,
                  workers: int = 2, deadline: float = None, cancel=None,
                  low_priority: bool = False, country: str = None, on_done=None,
                  want_udp: bool = False, metrics_out: dict = None):
    """Test nodes in temporary sing-box processes WITHOUT printing anything.

    level 0 = quick probe, 1/2 = quality gate (see FV_QUALITY_*).
    Returns (good, bad_tags): good = [(ob, delay_ms), ...] fastest first; bad_tags
    only contains nodes that were really tested and failed (skipped ones are not
    reported as bad). Uses plain daemon threads so a program exit never waits
    for a background test.
    """
    test_urls = ["https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"]
    todo = queue.Queue()
    for ob in nodes:
        todo.put(ob)
    good, bad = [], set()
    lock = threading.Lock()
    stop = threading.Event()

    def worker():
        if low_priority:
            try:  # lower CPU priority of this thread; child sing-box processes inherit it
                os.setpriority(os.PRIO_PROCESS, threading.get_native_id(), 10)
            except Exception:
                pass
        while not stop.is_set() and not (cancel is not None and cancel.is_set()):
            if deadline is not None and time.monotonic() > deadline:
                return
            try:
                ob = todo.get_nowait()
            except queue.Empty:
                return
            try:
                _m = {}
                ok, delay_ms, _err = _verify_one_fv_sublink(binary, ob, test_urls, quality=level,
                                                            metrics=_m, want_country=country,
                                                            want_udp=want_udp)
                if metrics_out is not None:
                    metrics_out[ob.get("tag")] = _m
            except Exception:
                ok, delay_ms = False, None
            if on_done is not None:
                try:
                    on_done(bool(ok and delay_ms is not None))
                except Exception:
                    pass
            if cancel is not None and cancel.is_set():
                return
            with lock:
                if ok and delay_ms is not None:
                    good.append((ob, delay_ms))
                    if stop_after and len(good) >= stop_after:
                        stop.set()
                else:
                    bad.add(ob.get("tag"))

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, workers))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    good.sort(key=lambda x: x[1])
    return good, bad


def _fetch_text_silent(url: str, via_proxy: bool) -> str:
    """Download a subscription text, either through the local proxy of the
    active connection (works even if the host is filtered) or directly."""
    req = urllib.request.Request(url, headers={"User-Agent": "sing-box"})
    with _proxied_opener(via_proxy).open(req, timeout=25) as resp:
        raw = resp.read()
    text = raw.decode("utf-8", errors="ignore").lstrip("\ufeff")
    if any(scheme in text.lower() for scheme in SUPPORTED_PROXY_SCHEMES):
        return text
    try:
        padded = raw + b"=" * (-len(raw) % 4)
        return base64.b64decode(padded, validate=True).decode("utf-8", errors="ignore").lstrip("\ufeff")
    except Exception:
        return text


def _raw_internet_up() -> bool:
    """True if the phone itself can reach the internet (a plain TCP connect,
    NOT through the VPN). Used so a dead phone connection is never mistaken for
    a dead server."""
    for host in (("1.1.1.1", 443), ("8.8.8.8", 443), ("9.9.9.9", 443)):
        try:
            with socket.create_connection(host, timeout=3):
                return True
        except OSError:
            continue
    return False


def _fv_health_probe() -> bool:
    """One real request through the local proxy of the running connection."""
    purl = f"http://127.0.0.1:{LOCAL_SOCKS_HTTP_PORT}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": purl, "https": purl}))
    for url in (URLTEST_URL, "https://cp.cloudflare.com/generate_204"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "RaminVPN-Watchdog/1.0",
                                                       "Cache-Control": "no-cache"})
            with opener.open(req, timeout=FV_HEALTH_TIMEOUT) as resp:
                resp.read(16)
            return True
        except Exception:
            continue
    return False


class _EpochCancel:
    """Cancel signal for a background search: program stopping OR the reserve
    was cleared (the user switched source) after the search started."""

    def __init__(self, stop_event, manager, epoch):
        self._stop, self._mgr, self._epoch = stop_event, manager, epoch

    def is_set(self) -> bool:
        return self._stop.is_set() or self._mgr._epoch != self._epoch


class ReserveManager:
    """Owns the stored reserve (fv_reserve.json), the silent background search
    that fills it up to FV_RESERVE_TARGET, and the connection watchdog."""

    def __init__(self, binary: str):
        self.binary = binary
        self._lock = threading.RLock()
        self._nodes = self._load()
        self._stop = threading.Event()
        self._scan_thread = None
        self._ai_thread = None   # silent AI Engine sweep (start_ai_scan)
        self._health_thread = None
        self._revalidated = False
        self._exhausted_at = 0.0
        self._notified_full = len(self._nodes) >= FV_RESERVE_TARGET
        self._dead_proc = None
        self._bad_fps = set()
        self._refresh_pending = False  # the reserve just became full: redraw the screen once
        self._full_shown = False
        self._displayed_count = 0      # how many reserve servers the last redraw already showed
        self._retry_gap = FV_RESERVE_RETRY_AFTER
        self._epoch = 0  # bumped by clear(): results of a search started before it are discarded
        self.site_feed = None   # SW "website": candidates of ONE searched site - while set, Switch Server
        self.site_label = None  # is filled from these ONLY (see set_site_feed / connect_by_site)
        self.ping_ceiling_ms = None  # T<n> command: background fill prefers candidates at/under
                                      # this real latency (see set_ping_ceiling / _scan_main)
        self._last_site_refresh = 0.0
        self.site_enough = None   # site feed: stop testing once the pool holds this many (None = SITE_SWITCH_MAX)
        self.site_hard_cap = None  # site feed: never store more than this many in total
        self.count_target = None  # SW "<protocol/country> <N>": Switch Server should hold N total (not site_feed)
        self.udp_only = False     # SW "udp" search: the background fill must ALSO pass the real UDP test
        self.country, self.country_name = self._load_country()  # set while a Type Country connection is active
        self.protocol, self.protocol_name = self._load_protocol()  # set while a Type Protocol connection is active

    # ---- storage --------------------------------------------------------
    def _load(self) -> list:
        try:
            with open(FV_RESERVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            nodes = data.get("nodes", []) if isinstance(data, dict) else []
            return [n for n in nodes if isinstance(n, dict) and n.get("tag") and n.get("type")][:max(FV_RESERVE_TARGET, AI_SWITCH_TARGET)]
        except Exception:
            return []

    def _load_country(self):
        try:
            with open(FV_RESERVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            cc = data.get("country")
            if isinstance(cc, str) and len(cc) == 2:
                return cc.upper(), data.get("country_name")
        except Exception:
            pass
        return None, None

    def _load_protocol(self):
        try:
            with open(FV_RESERVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            wanted = data.get("protocol")
            if isinstance(wanted, str) and wanted:
                return wanted, data.get("protocol_name") or wanted
        except Exception:
            pass
        return None, None

    def set_binding(self, country=None, country_name=None, protocol=None, protocol_name=None,
                    fresh: bool = False, count: int = None, udp_only: bool = False):
        """Bind the background search to a country and/or a protocol (Type Country /
        Type Protocol) or release both (no arguments). A changed binding - or fresh=True,
        used right after a brand-new search - forgets the stored nodes so Switch Server
        never mixes countries or protocols by accident. count: SW "<...> <N>" - Switch
        Server should hold N total instead of the usual pool size. udp_only: SW "udp" -
        the background fill must also pass the real UDP relay test."""
        with self._lock:
            same = (country == self.country and protocol == self.protocol
                    and (country is None or country_name == self.country_name)
                    and self.site_feed is None)   # any other binding releases a website source
            if same and not fresh and count == self.count_target and udp_only == self.udp_only:
                return
            self.country, self.country_name = country, country_name
            self.protocol, self.protocol_name = protocol, protocol_name
            self.count_target, self.udp_only = count, udp_only
        self.clear()

    def set_site_feed(self, candidates: list, label: str = None, bad_fps=None,
                      country: str = None, country_name: str = None,
                      enough: int = None, hard_cap: int = None) -> None:
        """SW "website": from now on the silent background search tests ONLY these
        candidates (the rest of the list found on the searched site) and stores the healthy
        ones, so "Switch Server : 1 - N" shows servers of that site and nothing else.
        Any other search (protocol / country / ping / FV source) releases it again."""
        with self._lock:
            self.country = self.country_name = None
            self.protocol = self.protocol_name = None
            self._epoch += 1
            self._nodes = []
            self._save()
            self._exhausted_at = 0.0
            self._retry_gap = FV_RESERVE_RETRY_AFTER
            self._full_shown = False
            self._refresh_pending = False
            self._notified_full = False
            self._displayed_count = 0
            self._revalidated = True          # nothing stored from an earlier session to re-check
            self._bad_fps = set(bad_fps or ())
            self.site_feed = [dict(ob) for ob in (candidates or [])]
            self.site_label = label
            self.site_enough, self.site_hard_cap = enough, hard_cap
            if country:   # Search Web + country: the site's servers must ALSO exit in that country
                self.country, self.country_name = country, country_name

    def set_country(self, code, name=None, count: int = None, udp_only: bool = False):
        """Bind the reserve to a country (Type Country) or release EVERY binding (None).
        Changing it forgets the stored nodes so Switch Server never mixes countries."""
        self.set_binding(country=code, country_name=name, count=count, udp_only=udp_only)

    def _target(self) -> int:
        """How many EXTRA servers the reserve should hold: the pool size the user is
        supposed to see (FV_POOL_TARGET_TOTAL) minus what the live pool already has."""
        have = len(_state.get("free_verified_pool") or [])
        if self.site_feed is not None:
            # SW "website": healthy servers of the site are kept (Switch Server : 1 - N) until
            # "enough" is reached (SITE_SWITCH_MAX for a plain site search, less for the
            # country / protocol / ping search that looks at freeproxydb first).
            return max(0, (self.site_enough or SITE_SWITCH_MAX) - have)
        if self.count_target:
            # SW "<protocol/country> <N>": Switch Server should hold exactly N total.
            return max(0, self.count_target - have)
        return max(0, min(FV_RESERVE_TARGET, FV_POOL_TARGET_TOTAL - have))

    def _add_cap(self) -> int:
        """How many stored servers add() accepts: normally the target, a little more for a
        site feed with a hard cap (servers that pass in the same batch as the last needed one)."""
        if self.site_feed is not None and self.site_hard_cap:
            have = len(_state.get("free_verified_pool") or [])
            return max(0, self.site_hard_cap - have)
        return self._target()

    def _pool_total(self) -> int:
        return max(1, len(_state.get("free_verified_pool") or [])) + self.count()

    def _save(self):
        try:
            tmp = FV_RESERVE_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"nodes": self._nodes, "updated": int(time.time()),
                           "country": self.country, "country_name": self.country_name,
                           "protocol": self.protocol, "protocol_name": self.protocol_name},
                          f, ensure_ascii=False, indent=1)
            os.replace(tmp, FV_RESERVE_PATH)
        except Exception:
            pass

    def snapshot(self) -> list:
        with self._lock:
            return [dict(n) for n in self._nodes]

    def count(self) -> int:
        with self._lock:
            return len(self._nodes)

    def add(self, good: list, epoch: int = None) -> int:
        """good = [(ob, delay_ms), ...]. Skips duplicates, never exceeds the target."""
        added = 0
        became_full = False
        with self._lock:
            if epoch is not None and epoch != self._epoch:
                return 0  # the reserve was cleared (source switched) while this batch was tested
            tags = {n["tag"] for n in self._nodes}
            fps = {_ob_fingerprint(n) for n in self._nodes}
            cap = self._add_cap()
            for ob, _delay in good:
                if len(self._nodes) >= cap:
                    break
                fp = _ob_fingerprint(ob)
                if fp in fps:
                    continue
                ob = dict(ob)
                if ob["tag"] in tags:  # same tag, different config: keep tags unique
                    ob["tag"] = f"{ob['tag']}~{len(tags)}"
                tags.add(ob["tag"])
                fps.add(fp)
                self._nodes.append(ob)
                added += 1
            if added:
                self._save()
            if added and self.site_feed is not None:
                now_m = time.monotonic()
                if now_m - self._last_site_refresh >= SITE_SWITCH_REFRESH_GAP:
                    self._last_site_refresh = now_m
                    self._refresh_pending = True   # redraw so "Switch Server : 1 - N" grows while testing
            if added and cap and len(self._nodes) >= cap and not self._full_shown:
                self._refresh_pending = True
            if cap and len(self._nodes) >= cap and not self._notified_full:
                self._notified_full = True
                became_full = True
        if became_full and FV_RESERVE_NOTIFY:
            send_notification("Free Vless", f"{self._pool_total()} سرور سالم ذخیره شد")
        return added

    def clear(self) -> None:
        """Forget every stored node (used when the user picks another Free Vless
        source, so Switch Server only shows servers of the source in use)."""
        with self._lock:
            self._epoch += 1
            self._nodes = []
            self._save()
            self._exhausted_at = 0.0
            self._retry_gap = FV_RESERVE_RETRY_AFTER
            self._full_shown = False
            self._refresh_pending = False
            self._notified_full = False
            self._displayed_count = 0
            self.site_feed = None     # switching source also drops a website source
            self.site_label = None
            self.ping_ceiling_ms = None   # a T<n> ceiling never carries into the next search

    def set_ping_ceiling(self, ms: float = None) -> None:
        """T<n> command only: the background fill will prefer candidates whose real,
        single-request latency is at or under `ms` - see _scan_main. Falls back to the
        closest-to-`ms` candidates found if the strict target can't be reached, so
        Switch Server still fills up to a useful minimum rather than staying empty."""
        with self._lock:
            self.ping_ceiling_ms = ms

    def remove_tags(self, tags) -> None:
        tags = set(tags or [])
        if not tags:
            return
        with self._lock:
            before = len(self._nodes)
            self._nodes = [n for n in self._nodes if n["tag"] not in tags]
            if len(self._nodes) != before:
                self._save()
                self._exhausted_at = 0.0  # there is room again: the search may resume at once
                if len(self._nodes) < self._target():
                    self._full_shown = False
                    self._refresh_pending = False

    def consume_full_refresh(self) -> bool:
        """True exactly once each time the reserve becomes full - the main loop
        then redraws the screen so Switch Server shows the new range."""
        with self._lock:
            if self._refresh_pending:
                self._refresh_pending = False
                self._full_shown = True
                self._displayed_count = len(self._nodes)
                return True
            return False

    def stop(self):
        self._stop.set()

    # ---- watchdog ---------------------------------------------------------
    def consume_health_dead(self, proc) -> bool:
        with self._lock:
            if self._dead_proc is not None and self._dead_proc is proc:
                self._dead_proc = None
                return True
            self._dead_proc = None
            return False

    def _health_main(self):
        last_proc, up_since, fails = None, 0.0, 0
        while not self._stop.wait(FV_HEALTH_INTERVAL):
            try:
                if not FV_HEALTH_ENABLED or not _state.get("free_vless_mode"):
                    fails = 0
                    continue
                proc = _state.get("proc")
                if proc is None or _state.get("cleaned_up") or proc.poll() is not None:
                    fails, last_proc = 0, None
                    continue
                now = time.monotonic()
                if proc is not last_proc:
                    last_proc, up_since, fails = proc, now, 0
                if now - up_since < FV_HEALTH_GRACE:
                    continue
                if _fv_health_probe():
                    fails = 0
                    continue
                fails = fails + 1 if _raw_internet_up() else 0
                if fails >= FV_HEALTH_MAX_FAILS:
                    fails = 0
                    with self._lock:
                        self._dead_proc = proc
            except Exception:
                continue

    # ---- background search ----------------------------------------------
    def tick(self, connected: bool):
        """Called by the main loop every few seconds. Starts the watchdog once
        and (re)starts the silent search whenever the reserve is not full."""
        if self._stop.is_set() or not connected:
            return
        if self._health_thread is None:
            self._health_thread = threading.Thread(target=self._health_main, daemon=True)
            self._health_thread.start()
        t = self._scan_thread
        if t is not None and t.is_alive():
            return
        at = self._ai_thread
        if at is not None and at.is_alive():
            return   # the AI sweep is running: do not start a second scanner next to it
        need_reval = (not self._revalidated) and self.count() > 0
        if not need_reval:
            if self.count() >= self._target():
                return
            if self._exhausted_at and time.monotonic() - self._exhausted_at < self._retry_gap:
                return
        self._scan_thread = threading.Thread(target=self._scan_main, daemon=True)
        self._scan_thread.start()

    # ---- AI Engine: silent sweep of the other sources --------------------------
    def start_ai_scan(self, seconds: float = None):
        """Right after the 'ai' command connected: for AI_SCAN_SECONDS silently go through the
        other Free Vless sources (best-ranked first, see source memory "ai:any"), verify every
        candidate with a real sing-box request on the phone's normal internet (the live tunnel
        is never touched), store the healthy ones as extra Switch Server numbers and teach the
        AI engine what worked (per source, per protocol, and a list of known-good servers)."""
        t = self._ai_thread
        if t is not None and t.is_alive():
            return
        self._ai_thread = threading.Thread(
            target=self._ai_scan_main, args=(float(seconds or AI_SCAN_SECONDS),), daemon=True)
        self._ai_thread.start()

    def _ai_scan_main(self, seconds: float):
        ep0 = self._epoch
        cancel = _EpochCancel(self._stop, self, ep0)
        deadline = time.monotonic() + seconds
        self._revalidated = True
        learned, saved = [], [0]

        def run_cands(key, ns, cands):
            """Test one source's candidates in small batches, store the healthy ones, teach the engine."""
            t0, tested, hits = time.monotonic(), 0, 0
            for i in range(0, len(cands), AI_SCAN_BATCH):
                if cancel.is_set() or time.monotonic() >= deadline or self.count() >= self._target():
                    break
                batch = cands[i:i + AI_SCAN_BATCH]
                by_tag = {ob["tag"]: ob for ob in batch}
                good, bad = _quiet_verify(self.binary, batch, level=0, workers=AI_SCAN_WORKERS,
                                          deadline=deadline, cancel=cancel, low_priority=True)
                tested += len(good) + len(bad)
                hits += len(good)
                for tg in bad:
                    ob = by_tag.get(tg)
                    if ob is not None:
                        self._bad_fps.add(_ob_fingerprint(ob))
                        AI.record(ob, False, save=False)
                for ob, _ms in good:
                    AI.record(ob, True, save=False)
                if good:
                    learned.extend(good)
                    saved[0] += self.add(good, epoch=ep0)
                time.sleep(FV_RESERVE_BATCH_PAUSE)
            if tested and not cancel.is_set():
                _SOURCE_MEMORY.record(ns, key, hits > 0, (time.monotonic() - t0) if hits else None)

        try:
            # 1) the protocol this user usually wants: its own feeds first (best-ranked first)
            wanted = UB.top_protocol()
            if wanted:
                defs = _protocol_source_defs(self.binary, wanted)
                builders = dict(defs)
                keys = [k for k, _b in defs
                        if k.startswith("EXTRA:") or k == "FPDB" or (k[:1] == "T" and k[1:].isdigit())]
                ns = f"proto:{wanted}"
                for key in _rank_sources(ns, keys)[:2]:
                    if cancel.is_set() or time.monotonic() >= deadline or self.count() >= self._target():
                        break
                    try:
                        skip = self._known_fingerprints()
                        cands = [ob for ob in builders[key]()
                                 if _ob_fingerprint(ob) not in skip][:AI_SCAN_PER_SOURCE]
                    except Exception:
                        cands = []
                    run_cands(key, ns, cands)

            # 2) every other source, best-ranked first
            order = _rank_sources("ai:any", [f"T{i + 1}" for i in range(len(FREE_VLESS_SOURCES))])
            srcs = [int(k[1:]) - 1 for k in order]
            ready = set()

            def prefetch(s_):
                try:
                    _fv_source_lines(s_)     # cached for 10 minutes; a slow host only delays itself
                except Exception:
                    pass
                finally:
                    ready.add(s_)

            for s_ in srcs[:AI_SCAN_PREFETCH]:
                threading.Thread(target=prefetch, args=(s_,), daemon=True).start()

            for pos, src in enumerate(srcs):
                if cancel.is_set() or time.monotonic() >= deadline or self.count() >= self._target():
                    break
                key = f"T{src + 1}"
                if pos < AI_SCAN_PREFETCH:
                    wait_until = min(deadline, time.monotonic() + 30.0)
                    while src not in ready and time.monotonic() < wait_until and not cancel.is_set():
                        time.sleep(0.25)
                    if src not in ready:
                        continue             # still downloading: skip without judging the source
                try:
                    lines = _fv_source_lines(src)
                except Exception:
                    lines = []
                if not lines:
                    if not cancel.is_set():
                        _SOURCE_MEMORY.record("ai:any", key, False)   # empty/unreachable source
                    continue
                try:
                    cands = self._candidates(src)[:AI_SCAN_PER_SOURCE]
                except Exception:
                    cands = []
                run_cands(key, "ai:any", cands)
        except Exception:
            pass
        finally:
            try:
                if learned:
                    AI.remember_good(learned)
                else:
                    AI.flush()
            except Exception:
                pass
            if self._epoch == ep0:
                self._exhausted_at = time.monotonic()
                self._retry_gap = FV_RESERVE_SATISFIED_RETRY   # the normal scanner waits before topping up
                with self._lock:
                    if self._nodes and len(self._nodes) != self._displayed_count:
                        self._refresh_pending = True            # one redraw: Switch Server shows the new range
                if saved[0]:
                    send_notification("AI Engine", f"{saved[0]} سرور سالم به Switch Server اضافه شد")

    def _should_stop(self) -> bool:
        return self._stop.is_set()

    def _known_fingerprints(self) -> set:
        fps = set(self._bad_fps)
        with self._lock:
            fps.update(_ob_fingerprint(n) for n in self._nodes)
        for ob in list(_state.get("free_verified_pool") or []):
            if isinstance(ob, dict):
                fps.add(_ob_fingerprint(ob))
        return fps

    def _candidates(self, src_index: int, ignore_country: bool = False) -> list:
        if self.country and not ignore_country:
            plan = _country_plan_for_source(src_index, self.country, 200, 100, skip=self._known_fingerprints())
            if self.udp_only and not self.protocol:
                plan = [ob for ob in plan if str(ob.get("type")) in UDP_CAPABLE_PROTOCOLS]
            return plan
        code = get_free_vless_source_code(src_index)
        lines = _fv_source_lines(src_index)
        if not lines:
            return []
        order = list(range(1, len(lines) + 1))
        random.shuffle(order)
        skip = self._known_fingerprints()
        out = []
        for i in order:
            try:
                ob = parse_proxy_uri(lines[i - 1], i, extended=True)
            except Exception:
                ob = None
            if not ob or _ob_fingerprint(ob) in skip:
                continue
            if self.udp_only and not self.protocol and str(ob.get("type")) not in UDP_CAPABLE_PROTOCOLS:
                continue
            ob["tag"] = f"FV-{code}-{ob['tag']}"
            out.append(ob)
            if len(out) >= FV_RESERVE_MAX_CANDIDATES:
                break
        return out

    # ---- candidate feeds --------------------------------------------------
    def _generic_feeds(self, ignore_country: bool = False):
        """Any-protocol candidates: the source the user is on first, then the rest in order.
        ignore_country=True: any protocol AND any country (the fill-up phase)."""
        if self.site_feed is not None:
            # SW "website": only the searched site's own list, best-ranked first
            feed, skip = self.site_feed, self._known_fingerprints
            yield None, (lambda: [ob for ob in feed if _ob_fingerprint(ob) not in skip()])
            return
        n_src = len(FREE_VLESS_SOURCES)
        first = int(_state.get("free_source_index") or 0) % n_src
        for k in range(n_src):
            src = (first + k) % n_src
            yield None, (lambda s=src: self._candidates(s, ignore_country))

    def _protocol_feeds(self):
        """Candidates of the bound protocol ONLY, as (memory key, builder) - best source first
        (see source_memory.py): the sources that delivered this protocol before, then unknown
        ones, then the ones that were empty."""
        wanted = self.protocol
        defs = _protocol_source_defs(self.binary, wanted, self.country)
        builders = dict(defs)
        skip = self._known_fingerprints
        for key in _rank_sources(f"proto:{wanted}", [k for k, _ in defs]):
            if key == "WARP":
                continue   # fresh WARP identities are only generated by an explicit search
            yield key, (lambda k=key: [ob for ob in builders[k]() if _ob_fingerprint(ob) not in skip()])

    def _scan_main(self):
        ep0 = self._epoch
        cancel = _EpochCancel(self._stop, self, ep0)
        started = time.monotonic()
        ceiling = self.ping_ceiling_ms
        over_ceiling_fallback = []   # T<n> only: candidates that passed but were slower than
                                     # `ceiling` - used to still reach FV_POOL_MIN_TOTAL if not
                                     # enough servers at/under the ceiling could be found in time
        try:
            if self._should_stop():
                return
            # 1) stored nodes from an earlier session may have died: quick re-check
            if not self._revalidated:
                nodes = self.snapshot()
                if nodes:
                    _good, bad = _quiet_verify(self.binary, nodes, level=0, workers=FV_RESERVE_WORKERS,
                                               cancel=cancel, low_priority=True)
                    if not self._should_stop() and self._epoch == ep0:
                        self.remove_tags(bad)
                if not self._should_stop():
                    self._revalidated = True
            # 2) search silently (the tests use the phone's normal internet: the temporary
            #    test processes dial the servers directly, the live tunnel is never touched).
            level = _fv_quality_level_now()
            if self.country:
                level = min(level, FV_COUNTRY_QUALITY_LEVEL)
            if self.protocol:
                level = 0  # QUIC/UDP based protocols are judged by the quick real-request probe
            # Phase "same": servers of the bound protocol (or, without a protocol, any server).
            # Phase "other": only when a protocol was requested and too few servers of that
            # protocol exist - other protocols fill the pool up to FV_POOL_MIN_TOTAL.
            bound = bool(self.protocol or self.country)
            site_scan = self.site_feed is not None   # a website list: test ALL of it, no soft stop
            phases = [("same", self._protocol_feeds if self.protocol else self._generic_feeds)]
            if bound:
                # Too few servers of that protocol / country: fill the list up to
                # FV_POOL_MIN_TOTAL with healthy servers of ANY protocol and country.
                phases.append(("other", lambda: self._generic_feeds(True)))
            for phase, feeds in phases:
                if phase == "other" and self._pool_total() >= FV_POOL_MIN_TOTAL:
                    break
                phase_start = time.monotonic()

                def need() -> int:
                    if phase == "other":
                        return FV_POOL_MIN_TOTAL - self._pool_total()
                    return self._target() - self.count()

                def satisfied() -> bool:
                    if need() <= 0:
                        return True
                    if site_scan:
                        return False
                    # enough servers for the minimum pool and the soft time budget is over
                    return (phase == "same" and self._pool_total() >= FV_POOL_MIN_TOTAL
                            and time.monotonic() - started > FV_RESERVE_SOFT_BUDGET)

                for feed_key, make_cands in feeds():
                    if self._should_stop() or satisfied():
                        break
                    if self._epoch != ep0:
                        return  # source switched: tick() restarts the search from the new source
                    if (bound and phase == "same"
                            and time.monotonic() - phase_start > FV_PROTOCOL_SAME_BUDGET):
                        break  # this protocol is scarce: let other protocols fill the pool
                    try:
                        cands = make_cands()
                    except Exception:
                        cands = []
                    site_mode = self.site_feed is not None
                    deadline = time.monotonic() + (FV_SITE_RESERVE_BUDGET if site_mode
                                                   else FV_RESERVE_SOURCE_BUDGET)
                    if bound and phase == "same":
                        deadline = min(deadline, phase_start + FV_PROTOCOL_SAME_BUDGET)
                    feed_t0, feed_got, feed_cut = time.monotonic(), 0, False
                    for i in range(0, len(cands), FV_RESERVE_BATCH):
                        if self._should_stop() or satisfied() or time.monotonic() > deadline:
                            feed_cut = True
                            break
                        if self._epoch != ep0:
                            return
                        batch = cands[i:i + FV_RESERVE_BATCH]
                        by_tag = {ob["tag"]: ob for ob in batch}
                        # A ceiling in effect: test the whole batch rather than stopping the
                        # instant `need()` loosely-good candidates turn up - most of those may
                        # still be slower than the ceiling, so a bigger sample is needed to find
                        # enough that actually qualify.
                        good, bad = _quiet_verify(self.binary, batch,
                                                  level=(level if phase == "same" else _fv_quality_level_now()),
                                                  stop_after=(None if ceiling else max(1, need())),
                                                  workers=(FV_SITE_RESERVE_WORKERS if site_mode
                                                           else FV_RESERVE_WORKERS),
                                                  deadline=deadline,
                                                  cancel=cancel, low_priority=True,
                                                  country=(self.country if phase == "same" else None),
                                                  want_udp=self.udp_only)
                        for t in bad:
                            if t in by_tag:
                                self._bad_fps.add(_ob_fingerprint(by_tag[t]))
                        if ceiling:
                            fast = [(ob, ms) for ob, ms in good if ms is not None and ms <= ceiling]
                            fast_tags = {ob.get("tag") for ob, _ms in fast}
                            over_ceiling_fallback.extend(x for x in good if x[0].get("tag") not in fast_tags)
                            good = fast
                        self.add(good, epoch=ep0)
                        feed_got += len(good)
                        time.sleep(FV_RESERVE_BATCH_PAUSE)
                    # result memory: remember which feed really delivered this protocol
                    if feed_key and self._epoch == ep0:
                        ns = f"proto:{self.protocol}"
                        if feed_got:
                            _SOURCE_MEMORY.record(ns, feed_key, True, time.monotonic() - feed_t0)
                        elif not feed_cut and not self.country:
                            _SOURCE_MEMORY.record(ns, feed_key, False)
            if self._epoch != ep0:
                return
            if ceiling and not self._should_stop() and self._epoch == ep0:
                still_need = FV_POOL_MIN_TOTAL - self._pool_total()
                if still_need > 0 and over_ceiling_fallback:
                    over_ceiling_fallback.sort(key=lambda x: x[1])
                    self.add(over_ceiling_fallback[:still_need], epoch=ep0)
            if not self._should_stop():
                # Enough for a useful Switch Server list -> top it up only rarely.
                ok_pool = self._pool_total() >= FV_POOL_MIN_TOTAL
                self._retry_gap = FV_RESERVE_SATISFIED_RETRY if ok_pool else FV_RESERVE_RETRY_AFTER
                if self.count() < self._target():
                    self._exhausted_at = time.monotonic()
            with self._lock:
                # one redraw so "Switch Server : 1 - N" shows the servers that were found
                if self._epoch == ep0 and len(self._nodes) and len(self._nodes) != self._displayed_count:
                    self._refresh_pending = True
        except Exception:
            self._exhausted_at = time.monotonic()


# ---------------------------------------------------------------------------
# Type Country
# ---------------------------------------------------------------------------
_COUNTRY_DATA = (
    "AD Andorra|AE United Arab Emirates|AF Afghanistan|AG Antigua and Barbuda|AI Anguilla|AL Albania|"
    "AM Armenia|AO Angola|AR Argentina|AS American Samoa|AT Austria|AU Australia|AW Aruba|AX Aland Islands|"
    "AZ Azerbaijan|BA Bosnia and Herzegovina|BB Barbados|BD Bangladesh|BE Belgium|BF Burkina Faso|"
    "BG Bulgaria|BH Bahrain|BI Burundi|BJ Benin|BM Bermuda|BN Brunei|BO Bolivia|BR Brazil|BS Bahamas|"
    "BT Bhutan|BW Botswana|BY Belarus|BZ Belize|CA Canada|CD DR Congo|CF Central African Republic|"
    "CG Congo|CH Switzerland|CI Ivory Coast|CK Cook Islands|CL Chile|CM Cameroon|CN China|CO Colombia|"
    "CR Costa Rica|CU Cuba|CV Cape Verde|CW Curacao|CY Cyprus|CZ Czechia|DE Germany|DJ Djibouti|"
    "DK Denmark|DM Dominica|DO Dominican Republic|DZ Algeria|EC Ecuador|EE Estonia|EG Egypt|ER Eritrea|"
    "ES Spain|ET Ethiopia|FI Finland|FJ Fiji|FO Faroe Islands|FR France|GA Gabon|GB United Kingdom|"
    "GD Grenada|GE Georgia|GF French Guiana|GG Guernsey|GH Ghana|GI Gibraltar|GL Greenland|GM Gambia|"
    "GN Guinea|GP Guadeloupe|GQ Equatorial Guinea|GR Greece|GT Guatemala|GU Guam|GW Guinea-Bissau|"
    "GY Guyana|HK Hong Kong|HN Honduras|HR Croatia|HT Haiti|HU Hungary|ID Indonesia|IE Ireland|"
    "IL Israel|IM Isle of Man|IN India|IQ Iraq|IR Iran|IS Iceland|IT Italy|JE Jersey|JM Jamaica|"
    "JO Jordan|JP Japan|KE Kenya|KG Kyrgyzstan|KH Cambodia|KI Kiribati|KM Comoros|"
    "KN Saint Kitts and Nevis|KP North Korea|KR South Korea|KW Kuwait|KY Cayman Islands|KZ Kazakhstan|"
    "LA Laos|LB Lebanon|LC Saint Lucia|LI Liechtenstein|LK Sri Lanka|LR Liberia|LS Lesotho|LT Lithuania|"
    "LU Luxembourg|LV Latvia|LY Libya|MA Morocco|MC Monaco|MD Moldova|ME Montenegro|MG Madagascar|"
    "MK North Macedonia|ML Mali|MM Myanmar|MN Mongolia|MO Macao|MQ Martinique|MR Mauritania|MT Malta|"
    "MU Mauritius|MV Maldives|MW Malawi|MX Mexico|MY Malaysia|MZ Mozambique|NA Namibia|NC New Caledonia|"
    "NE Niger|NG Nigeria|NI Nicaragua|NL Netherlands|NO Norway|NP Nepal|NZ New Zealand|OM Oman|"
    "PA Panama|PE Peru|PF French Polynesia|PG Papua New Guinea|PH Philippines|PK Pakistan|PL Poland|"
    "PR Puerto Rico|PS Palestine|PT Portugal|PY Paraguay|QA Qatar|RE Reunion|RO Romania|RS Serbia|"
    "RU Russia|RW Rwanda|SA Saudi Arabia|SC Seychelles|SD Sudan|SE Sweden|SG Singapore|SI Slovenia|"
    "SK Slovakia|SL Sierra Leone|SM San Marino|SN Senegal|SO Somalia|SR Suriname|SS South Sudan|"
    "SV El Salvador|SY Syria|SZ Eswatini|TD Chad|TG Togo|TH Thailand|TJ Tajikistan|TL Timor-Leste|"
    "TM Turkmenistan|TN Tunisia|TO Tonga|TR Turkey|TT Trinidad and Tobago|TW Taiwan|TZ Tanzania|"
    "UA Ukraine|UG Uganda|US United States|UY Uruguay|UZ Uzbekistan|VA Vatican City|"
    "VC Saint Vincent and the Grenadines|VE Venezuela|VG British Virgin Islands|VI US Virgin Islands|"
    "VN Vietnam|VU Vanuatu|WS Samoa|XK Kosovo|YE Yemen|ZA South Africa|ZM Zambia|ZW Zimbabwe"
)
COUNTRY_NAMES = {item[:2]: item[3:] for item in _COUNTRY_DATA.split("|")}
_COUNTRY_ALIASES = {
    "usa": "US", "america": "US", "united states of america": "US", "the united states": "US",
    "uk": "GB", "britain": "GB", "great britain": "GB", "england": "GB", "scotland": "GB",
    "uae": "AE", "emirates": "AE", "dubai": "AE", "holland": "NL", "the netherlands": "NL",
    "nederland": "NL", "czech republic": "CZ", "korea": "KR", "republic of korea": "KR",
    "turkiye": "TR", "türkiye": "TR", "ivory coast": "CI", "cote d ivoire": "CI",
    "russian federation": "RU", "viet nam": "VN", "hongkong": "HK", "macau": "MO", "burma": "MM",
    "swaziland": "SZ", "east timor": "TL", "vatican": "VA", "persia": "IR", "deutschland": "DE",
    "espana": "ES", "brasil": "BR", "suisse": "CH", "schweiz": "CH", "osterreich": "AT",
}
_COUNTRY_FA = {
    "آلمان": "DE", "فرانسه": "FR", "انگلیس": "GB", "بریتانیا": "GB", "انگلستان": "GB", "آمریکا": "US",
    "امریکا": "US", "ایالات متحده": "US", "هلند": "NL", "ترکیه": "TR", "ژاپن": "JP", "کانادا": "CA",
    "سوئد": "SE", "سوئیس": "CH", "فنلاند": "FI", "نروژ": "NO", "دانمارک": "DK", "ایتالیا": "IT",
    "اسپانیا": "ES", "روسیه": "RU", "اوکراین": "UA", "لهستان": "PL", "رومانی": "RO", "بلغارستان": "BG",
    "اتریش": "AT", "بلژیک": "BE", "ایرلند": "IE", "پرتغال": "PT", "یونان": "GR", "امارات": "AE",
    "عربستان": "SA", "قطر": "QA", "بحرین": "BH", "کویت": "KW", "عمان": "OM", "ارمنستان": "AM",
    "آذربایجان": "AZ", "گرجستان": "GE", "هند": "IN", "پاکستان": "PK", "چین": "CN", "هنگ کنگ": "HK",
    "تایوان": "TW", "کره جنوبی": "KR", "سنگاپور": "SG", "مالزی": "MY", "اندونزی": "ID", "تایلند": "TH",
    "ویتنام": "VN", "فیلیپین": "PH", "استرالیا": "AU", "نیوزیلند": "NZ", "برزیل": "BR",
    "آرژانتین": "AR", "مکزیک": "MX", "شیلی": "CL", "مصر": "EG", "آفریقای جنوبی": "ZA",
    "اسرائیل": "IL", "عراق": "IQ", "ایران": "IR", "افغانستان": "AF", "قزاقستان": "KZ",
    "ازبکستان": "UZ", "لتونی": "LV", "لیتوانی": "LT", "استونی": "EE", "چک": "CZ", "مجارستان": "HU",
    "صربستان": "RS", "کرواسی": "HR", "قبرس": "CY", "مالت": "MT", "لوکزامبورگ": "LU", "ایسلند": "IS",
    "مولداوی": "MD", "بلاروس": "BY", "اردن": "JO", "لبنان": "LB", "سوریه": "SY", "مراکش": "MA",
    "الجزایر": "DZ", "تونس": "TN", "کنیا": "KE", "نیجریه": "NG", "کلمبیا": "CO", "پرو": "PE",
    "ونزوئلا": "VE", "کوبا": "CU", "اسلوونی": "SI", "اسلواکی": "SK", "آلبانی": "AL", "بوسنی": "BA",
    "مونته نگرو": "ME", "ترکمنستان": "TM", "قرقیزستان": "KG", "تاجیکستان": "TJ", "مغولستان": "MN",
    "نپال": "NP", "بنگلادش": "BD", "سریلانکا": "LK", "کامبوج": "KH", "میانمار": "MM",
}
_COUNTRY_INDEX = None  # normalized name/alias -> ISO code (built on first use)


def _norm_country_text(text: str) -> str:
    t = str(text or "").strip().lower()
    t = t.replace("\u200c", " ").replace("ي", "ی").replace("ك", "ک")
    return re.sub(r"[\s_\-.,]+", " ", t).strip()


def _country_index() -> dict:
    global _COUNTRY_INDEX
    if _COUNTRY_INDEX is None:
        idx = {}
        for code, name in COUNTRY_NAMES.items():
            idx[_norm_country_text(name)] = code
        for alias, code in _COUNTRY_ALIASES.items():
            idx[_norm_country_text(alias)] = code
        for fa, code in _COUNTRY_FA.items():
            idx[_norm_country_text(fa)] = code
        _COUNTRY_INDEX = idx
    return _COUNTRY_INDEX


def resolve_country(text: str):
    """(ISO code, English name) for what the user typed, or None. Accepts English
    names/aliases (Germany, UK, USA...), Persian names and small typos. Bare 2-letter
    codes are NOT accepted (too easy to type by accident: no, in, it, me...).
    Existing commands are handled before this is ever consulted."""
    t = _norm_country_text(text)
    if not t or t.isdigit() or len(t) > 40:
        return None
    idx = _country_index()
    code = idx.get(t)
    if code is None and len(t) >= 3:
        # Prefer the user's curated 25-country list for short prefixes. This
        # makes "Ame" unambiguously mean America/United States instead of
        # colliding with unrelated ISO entries such as American Samoa.
        curated = {
            "america": "US", "england": "GB", "germany": "DE",
            "netherlands": "NL", "france": "FR", "canada": "CA",
            "switzerland": "CH", "sweden": "SE", "norway": "NO",
            "finland": "FI", "denmark": "DK", "italy": "IT",
            "spain": "ES", "austria": "AT", "belgium": "BE",
            "poland": "PL", "romania": "RO", "turkey": "TR",
            "japan": "JP", "singapore": "SG", "australia": "AU",
            "india": "IN", "brazil": "BR", "hong kong": "HK",
            "emirates": "AE",
        }
        prefix_matches = sorted({v for k, v in curated.items() if k.startswith(t)})
        if len(prefix_matches) == 1:
            code = prefix_matches[0]
        else:
            # Fall back to the complete alias table only when the curated list
            # is not enough; ambiguous prefixes remain rejected.
            prefix_matches = sorted({v for k, v in idx.items() if k.startswith(t)})
            if len(prefix_matches) == 1:
                code = prefix_matches[0]
    if code is None and len(t) >= 5 and t.isascii():
        import difflib
        near = difflib.get_close_matches(t, list(idx.keys()), n=1, cutoff=0.86)
        if near:
            code = idx[near[0]]
    if code is None:
        return None
    return code, COUNTRY_NAMES.get(code, code)


def _country_match_terms(code: str) -> tuple:
    """(flag emoji, long names, short tokens) used to spot a country in a config name."""
    flag = "".join(chr(0x1F1E6 + ord(c) - 65) for c in code)
    names, tokens = [], {code.lower()}
    for k, v in _country_index().items():
        if v != code:
            continue
        if len(k) >= 4:
            names.append(k)
        else:
            tokens.add(k)
    return flag, names, tokens


_COUNTRY_TERMS_CACHE = {}


def _remark_matches_country(remark: str, code: str) -> bool:
    """Cheap guess from a config's name. It only decides testing ORDER: the real
    exit country of every candidate is verified through its own tunnel."""
    if not remark:
        return False
    terms = _COUNTRY_TERMS_CACHE.get(code)
    if terms is None:
        terms = _COUNTRY_TERMS_CACHE[code] = _country_match_terms(code)
    flag, names, tokens = terms
    if flag in remark:
        return True
    low = _norm_country_text(remark)
    if any(n in low for n in names):
        return True
    for tk in tokens:
        if tk.isascii():
            if re.search(r"(?<![a-z])" + re.escape(tk) + r"(?![a-z])", low):
                return True
        elif tk in low:  # short Persian names
            return True
    return False


def _line_remark(line: str) -> str:
    if line.startswith("vmess://"):
        try:
            raw = line[8:]
            raw += "=" * (-len(raw) % 4)
            return str(json.loads(base64.b64decode(raw).decode("utf-8", errors="ignore")).get("ps", ""))
        except Exception:
            return ""
    if "#" in line:
        return urllib.parse.unquote(line.split("#", 1)[1])
    return ""


_FV_SOURCE_CACHE = {}  # source index -> (fetched at, config lines)


def _fv_source_lines(src_index: int) -> list:
    """Config lines of one Free Vless source (cached for 10 minutes). Downloaded
    through the local proxy of the active connection when there is one (works even
    if the host is filtered), otherwise / afterwards directly."""
    now = time.monotonic()
    hit = _FV_SOURCE_CACHE.get(src_index)
    if hit and now - hit[0] < 600:
        return hit[1]
    url = FREE_VLESS_SOURCES[src_index]
    proc = _state.get("proc")
    alive = proc is not None and proc.poll() is None
    text = ""
    for via_proxy in ([True, False] if alive else [False, True]):
        try:
            text = _fetch_text_silent(url, via_proxy)
            if text:
                break
        except Exception:
            continue
    lines, seen = [], set()
    for line in (text or "").splitlines():
        line = line.strip().lstrip("\ufeff")
        if line and line.startswith(SUPPORTED_PROXY_SCHEMES) and line not in seen:
            seen.add(line)
            lines.append(line)
    if not lines and text:
        # Plain "does the line start with a scheme" extraction (above) misses
        # Telegram's web-preview HTML, where each link is wrapped in markup
        # rather than sitting alone on its own line - fall back to the same
        # regex-over-arbitrary-text scan fetch_telegram_channel_configs() uses,
        # so a t.me/s/<channel> entry in FREE_VLESS_SOURCES actually contributes
        # to protocol search too, not just to the Free Vless (FV) pool.
        try:
            for uri in extract_proxy_uris_from_text(text):
                if uri not in seen:
                    seen.add(uri)
                    lines.append(uri)
        except Exception:
            pass
    if lines:
        _FV_SOURCE_CACHE[src_index] = (now, lines)
    return lines



_PROTOCOL_EXTRA_CACHE = {}


def _protocol_extra_lines(url: str, cache_key: str = None) -> list:
    """Fetch a protocol-specialized public feed and return only supported URI lines.

    The cache is deliberately short-lived so protocol search remains fresh while
    avoiding repeated downloads/rate-limit hits when a user retries the same query.
    """
    key = cache_key or url
    now = time.monotonic()
    hit = _PROTOCOL_EXTRA_CACHE.get(key)
    if hit and now - hit[0] < FREEPROXYDB_EXTRA_CACHE_TTL:
        return hit[1]

    proc = _state.get("proc")
    alive = proc is not None and proc.poll() is None
    text = ""
    for via_proxy in ([True, False] if alive else [False, True]):
        try:
            text = _fetch_text_silent(url, via_proxy)
            if text:
                break
        except Exception:
            continue

    lines, seen = [], set()
    for line in (text or "").splitlines():
        line = line.strip().lstrip("\ufeff")
        if line and line.startswith(SUPPORTED_PROXY_SCHEMES) and line not in seen:
            seen.add(line)
            lines.append(line)
    if not lines and text:
        # Same Telegram-HTML fallback as _fv_source_lines() - see its comment.
        try:
            for uri in extract_proxy_uris_from_text(text):
                if uri not in seen:
                    seen.add(uri)
                    lines.append(uri)
        except Exception:
            pass
    if lines:
        _PROTOCOL_EXTRA_CACHE[key] = (now, lines)
    return lines


def _freeproxydb_protocol_lines(wanted: str) -> list:
    """Fetch FreeProxyDB's public, no-key subscription endpoint for one protocol.

    FreeProxyDB documents per-IP public rate limits, so this is cached and only
    one protocol-specific request is made per search/retry window. Unsupported
    FreeProxyDB-only types such as MTProto/SSR are intentionally not requested.
    """
    api_protocol = FREEPROXYDB_PROTOCOL_MAP.get(wanted)
    if not api_protocol:
        return []
    params = urllib.parse.urlencode({
        "count": 100,
        "protocol": api_protocol,
        "subscribe_format": "original",
    })
    url = f"{FREEPROXYDB_API_URL}?{params}"

    # The public API allows only 3 subscribe calls/minute/IP. Coordinate calls
    # across protocol searches so rapidly switching protocols cannot accidentally
    # exhaust that quota. Cached protocol feeds return immediately.
    global _FREEPROXYDB_LAST_REQUEST
    now = time.monotonic()
    with _FREEPROXYDB_RATE_LOCK:
        wait = FREEPROXYDB_MIN_REQUEST_GAP - (now - _FREEPROXYDB_LAST_REQUEST)
        if wait > 0:
            time.sleep(wait)
        _FREEPROXYDB_LAST_REQUEST = time.monotonic()
    return _protocol_extra_lines(url, cache_key=f"freeproxydb:{api_protocol}")


# ---- GitHub discovery: NEW repos found by live search, not the fixed list above ----

_DISCOVERY_MEMORY = SourceMemory(DISCOVERED_SOURCES_PATH)  # same scoring engine as
# _SOURCE_MEMORY, just a separate file: forgets/relearns discovered repos and channels
# independently of the T1-Tn result memory.


def _github_headers() -> dict:
    h = {"Accept": "application/vnd.github+json", "User-Agent": "RaminVPN-discovery"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


def _github_api_get(path_and_query: str) -> dict:
    """One rate-limited GET against the GitHub REST API. Tries through the active
    tunnel first (api.github.com can be blocked directly the same as t.me/raw.
    githubusercontent.com), then direct. A dead/blocked/rate-limited API must
    behave exactly like an empty feed - so this never raises, only returns {}."""
    global _GITHUB_LAST_REQUEST
    with _GITHUB_RATE_LOCK:
        wait = GITHUB_DISCOVERY_MIN_REQUEST_GAP - (time.monotonic() - _GITHUB_LAST_REQUEST)
        if wait > 0:
            time.sleep(wait)
        _GITHUB_LAST_REQUEST = time.monotonic()
    req = urllib.request.Request(f"{GITHUB_API_BASE}{path_and_query}", headers=_github_headers())
    proc = _state.get("proc")
    alive = proc is not None and proc.poll() is None
    for via_proxy in ([True, False] if alive else [False, True]):
        try:
            with _proxied_opener(via_proxy).open(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8", errors="ignore"))
        except Exception:
            continue
    return {}


def _github_fetch_file(repo: str, path: str) -> str:
    """raw.githubusercontent.com FIRST: no token and no 60/hour API cap for
    unauthenticated users (the Contents API hits that cap after just a few
    searches). Only the branch name has to be guessed, so main then master
    are tried; the Contents API stays as the fallback for repos whose default
    branch is neither (and for API-shaped edge cases)."""
    quoted = urllib.parse.quote(path)
    for branch in ("main", "master"):
        text = _fetch_page_text(
            f"https://raw.githubusercontent.com/{repo}/{branch}/{quoted}", timeout=15)
        if text and not text.lstrip().startswith("404:"):
            return text
    data = _github_api_get(f"/repos/{repo}/contents/{quoted}")
    content = data.get("content") if isinstance(data, dict) else None
    if not content:
        return ""
    try:
        return base64.b64decode(content, validate=False).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _proxy_lines_from_text(text: str) -> list:
    """Same line-extraction _protocol_extra_lines() does for a fetched URL, but for
    text already in hand. Falls back to extract_proxy_uris_from_text() so links buried
    inside a README/markdown paragraph are still found, not just whole-line ones."""
    lines, seen = [], set()
    for line in (text or "").splitlines():
        line = line.strip().lstrip("\ufeff")
        if line and line.startswith(SUPPORTED_PROXY_SCHEMES) and line not in seen:
            seen.add(line)
            lines.append(line)
    if not lines and text:
        try:
            for uri in extract_proxy_uris_from_text(text):
                if uri not in seen:
                    seen.add(uri)
                    lines.append(uri)
        except Exception:
            pass
    return lines


def _github_search_repos_html(query_terms: list, max_repos: int) -> list:
    """Token-less HTML fallback: scrape github.com/search (repositories) when the
    Search API is rate-limited or unreachable. The HTML page is a different
    endpoint with its own limits, so one being exhausted does not mean the
    other is. Silent + best-effort like everything else here."""
    q = " ".join(query_terms)
    page = _fetch_page_text(
        f"https://github.com/search?q={urllib.parse.quote(q)}&type=repositories", timeout=20)
    repos, seen = [], set()
    for m in re.finditer(r'href="/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"', page or ""):
        full = m.group(1)
        if full.count("/") != 1 or full.endswith((".md", ".py", ".txt")):
            continue
        owner, name = full.split("/", 1)
        if owner in ("topics", "collections", "orgs", "users", "search", "settings")                 or name in ("stargazers", "forks", "issues", "pulls"):
            continue
        if full not in seen:
            seen.add(full)
            repos.append(full)
        if len(repos) >= max_repos:
            break
    return repos


def _github_search_repos(query_terms: list, max_repos: int) -> list:
    """Repository Search API - finds NEW repos by name/description/README. Works with
    NO token (10 req/min, the same limit GitHub applies to unauthenticated search).
    Falls back to the HTML search page when the API yields nothing (rate-limited,
    blocked or offline), so token-less discovery keeps working either way."""
    q = " ".join(query_terms) + " in:name,description,readme"
    data = _github_api_get(f"/search/repositories?q={urllib.parse.quote(q)}"
                           f"&sort=updated&order=desc&per_page={max_repos}")
    items = data.get("items") if isinstance(data, dict) else None
    repos = [it.get("full_name") for it in (items or [])[:max_repos] if it.get("full_name")]
    if repos:
        return repos
    return _github_search_repos_html(query_terms, max_repos)


def _github_search_code(query_terms: list, max_files: int) -> list:
    """Code Search API - finds files whose CONTENT mentions the terms, catching repos
    the repo-name search above misses entirely. Requires a token (GitHub's own rule);
    silently contributes nothing without one, matching every other optional source here."""
    if not GITHUB_TOKEN:
        return []
    q = " ".join(query_terms)
    data = _github_api_get(f"/search/code?q={urllib.parse.quote(q)}&per_page={max_files}")
    items = data.get("items") if isinstance(data, dict) else None
    out = []
    for it in (items or [])[:max_files]:
        repo = (it.get("repository") or {}).get("full_name")
        path = it.get("path")
        if repo and path:
            out.append((repo, path))
    return out


def discover_github_sources(wanted: str, max_count: int, extra_terms: list = None) -> list:
    """Search GitHub LIVE for repos publishing free `wanted`-protocol configs that
    aren't in the fixed FREE_VLESS_SOURCES / PROTOCOL_EXTRA_SOURCE_URLS lists at all,
    and return parsed candidates in the exact shape every other protocol source
    returns. Repos that pay off are remembered (_DISCOVERY_MEMORY) and tried again,
    directly, before the next live search - so a rate-limited or offline GitHub still
    benefits from what was learned before. Fully optional and silent: any failure
    (offline, rate-limited, API shape change, no token) yields [] like an empty feed,
    never raises, and never blocks any other source in the same search."""
    if not GITHUB_DISCOVERY_ENABLED:
        return []
    canonical = _PROTOCOL_CANONICAL.get(wanted, wanted)
    terms = [canonical] + (extra_terms or []) + ["v2ray OR xray OR config"]
    cache_key = f"{wanted}:{'|'.join(extra_terms or [])}"
    now = time.monotonic()
    hit = _GITHUB_DISCOVERY_CACHE.get(cache_key)
    if hit and now - hit[0] < GITHUB_DISCOVERY_CACHE_TTL:
        return hit[1]

    ns = f"gh:{wanted}"
    lines, tried = [], set()

    def try_repo(repo: str) -> bool:
        if repo in tried or len(tried) >= GITHUB_DISCOVERY_MAX_REPOS:
            return False
        tried.add(repo)
        found = False
        for fname in GITHUB_DISCOVERY_CANDIDATE_FILES[:GITHUB_DISCOVERY_MAX_FILES_PER_REPO]:
            try:
                text = _github_fetch_file(repo, fname)
            except Exception:
                text = ""
            got = _proxy_lines_from_text(text)
            if got:
                lines.extend(got)
                found = True
        return found

    try:
        # Known-good repos from earlier searches first - no API call needed at all.
        remembered = [k for k, s in _DISCOVERY_MEMORY.summary(ns) if s > 0.35]
        for repo in remembered:
            try_repo(repo)

        for repo in _github_search_repos(terms, GITHUB_DISCOVERY_MAX_REPOS):
            if repo in tried:
                continue
            _DISCOVERY_MEMORY.record(ns, repo, try_repo(repo))

        for repo, path in _github_search_code(terms, GITHUB_DISCOVERY_MAX_FILES_PER_REPO * 2):
            try:
                text = _github_fetch_file(repo, path)
            except Exception:
                text = ""
            got = _proxy_lines_from_text(text)
            if got:
                lines.extend(got)
            _DISCOVERY_MEMORY.record(ns, repo, bool(got))
    except Exception:
        pass

    plan = _protocol_plan_from_lines(lines, wanted, max_count, tag_prefix="PX-GitHub_Discovery-")
    _GITHUB_DISCOVERY_CACHE[cache_key] = (now, plan)
    return plan


# ---- Telegram discovery: NEW public channels found by live global search ----

def _telethon_available() -> bool:
    try:
        import telethon  # noqa: F401
        return True
    except Exception:
        return False


def _telegram_client():
    """A logged-in Telethon client using the session telegram_login.py created, or
    None if credentials/session/library are missing - discovery is then silently
    skipped, exactly like an empty feed."""
    if not (TELEGRAM_DISCOVERY_ENABLED and TELEGRAM_API_ID and TELEGRAM_API_HASH
            and os.path.exists(TELEGRAM_SESSION_FILE) and _telethon_available()):
        return None
    try:
        from telethon.sync import TelegramClient
        client = TelegramClient(TELEGRAM_SESSION_FILE, int(TELEGRAM_API_ID), TELEGRAM_API_HASH)
        client.connect()
        if not client.is_user_authorized():
            client.disconnect()
            return None
        return client
    except Exception:
        return None



# ---- Live WEB discovery: Google-style whole-web search (no API key needed) ----
# Searches the live web for pages/channels publishing free configs of the wanted
# protocol (DuckDuckGo HTML endpoint, SearXNG public instances as fallback), fetches
# the top hits, and parses them with the exact same parser/verification/memory as
# every other source. Telegram channels are covered WITHOUT any login via the
# site:t.me/s/ queries (search engines index public t.me preview pages) AND by
# scanning every fetched page for t.me channel links. Optional and silent: any
# failure (offline, rate-limited, blocked) yields [] like an empty feed.
# ---- SW "@channel": named Telegram channel read through the tunnel ----
SW_CHANNEL_EXTRA_PROTOCOLS = (
    "vless", "vmess", "trojan", "hysteria2", "hysteria", "ss",
    "tuic", "wireguard", "anytls", "shadowtls", "socks", "ssh",
)
SW_CHANNEL_SILENT_TARGET = 10     # healthy extra-protocol servers to find silently
SW_CHANNEL_MAX_CANDIDATES = 40
WEB_DISCOVERY_FETCH_VIA_VPN = True  # download searched pages through the tunnel when up

WEB_DISCOVERY_ENABLED = True
WEB_DISCOVERY_MAX_RESULTS = 10        # search-result pages inspected per query
WEB_DISCOVERY_EXTRA_URL_SLOTS = 8     # remembered good URLs tried on top of fresh hits
WEB_DISCOVERY_MAX_TG_CHANNELS = 8     # t.me channels followed per search
WEB_DISCOVERY_FREETEXT_MAX = 30       # max candidates for an SW free-text query
WEB_DISCOVERY_CACHE_TTL = 900.0       # seconds - don't re-run the same query back to back
WEB_DISCOVERY_MIN_REQUEST_GAP = 2.0   # be polite to search engines
WEB_DISCOVERY_SEARXNG_INSTANCES = (   # key-less fallback engines, tried in order
    "https://search.inetol.net/search",
    "https://searx.be/search",
    "https://search.bus-hit.me/search",
)
_WEB_DISCOVERY_CACHE = {}
_WEB_LAST_REQUEST = 0.0
_WEB_RATE_LOCK = threading.Lock()
_WEB_SEARCH_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def _web_throttle() -> None:
    global _WEB_LAST_REQUEST
    with _WEB_RATE_LOCK:
        wait = WEB_DISCOVERY_MIN_REQUEST_GAP - (time.monotonic() - _WEB_LAST_REQUEST)
        if wait > 0:
            time.sleep(wait)
        _WEB_LAST_REQUEST = time.monotonic()


def _fetch_page_text(url: str, timeout: int = 20) -> str:
    """Fetch a page as text: through the active tunnel FIRST when one is up
    (most result pages and t.me are filtered directly in places like Iran),
    direct as a fallback - or direct first when there is no tunnel yet.
    Scripts and styles are stripped so the regex parser sees mostly real content.
    Set WEB_DISCOVERY_FETCH_VIA_VPN = False to restore always-direct fetches."""
    tunnel_first = WEB_DISCOVERY_FETCH_VIA_VPN and _local_tunnel_up(refresh=0)
    order = [True, False] if tunnel_first else [False, True]
    for via_proxy in order:
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": _WEB_SEARCH_UA, "Accept-Language": "en-US,en;q=0.8"})
            with _proxied_opener(via_proxy).open(req, timeout=timeout) as resp:
                raw = resp.read(2_000_000)
            text = raw.decode("utf-8", errors="ignore")
            return re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
        except Exception:
            continue
    return ""


def _ddg_search_urls(query: str, limit: int) -> list:
    """DuckDuckGo's HTML endpoint - the closest no-key equivalent of a Google
    search. Tries through the active tunnel FIRST when one is up (duckduckgo.com
    can be filtered directly too), direct as a fallback. Returns up to `limit`
    real result URLs."""
    urls, seen = [], set()
    order = [True, False] if _local_tunnel_up(refresh=0) else [False, True]
    for endpoint in ("https://html.duckduckgo.com/html/", "https://duckduckgo.com/html/"):
        for via_proxy in order:
            try:
                data = urllib.parse.urlencode({"q": query, "kl": "us-en"}).encode()
                req = urllib.request.Request(endpoint, data=data, headers={
                    "User-Agent": _WEB_SEARCH_UA,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": "https://duckduckgo.com/"})
                _web_throttle()
                with _proxied_opener(via_proxy).open(req, timeout=20) as resp:
                    page = resp.read(2_000_000).decode("utf-8", errors="ignore")
            except Exception:
                continue
            for m in re.finditer(r'class="result__a"[^>]*href="([^"]+)"', page):
                href = html_lib.unescape(m.group(1))
                parsed = urllib.parse.urlparse(href)
                if parsed.netloc.endswith("duckduckgo.com"):
                    href = urllib.parse.parse_qs(parsed.query).get("uddg", [href])[0]
                if href.startswith("http") and href not in seen:
                    seen.add(href)
                    urls.append(href)
            if urls:
                break
        if urls:
            break
    return urls[:limit]


def _searxng_search_urls(query: str, limit: int) -> list:
    """Fallback search via public SearXNG instances (JSON API, no key). Tries
    through the active tunnel FIRST when one is up, direct as a fallback."""
    urls, seen = [], set()
    order = [True, False] if _local_tunnel_up(refresh=0) else [False, True]
    for inst in WEB_DISCOVERY_SEARXNG_INSTANCES:
        for via_proxy in order:
            try:
                url = inst + "?" + urllib.parse.urlencode(
                    {"q": query, "format": "json", "safesearch": 0})
                _web_throttle()
                req = urllib.request.Request(url, headers={"User-Agent": _WEB_SEARCH_UA})
                with _proxied_opener(via_proxy).open(req, timeout=15) as resp:
                    data = json.loads(resp.read(1_000_000).decode("utf-8", errors="ignore"))
                for r in data.get("results", []):
                    u = r.get("url", "")
                    if u.startswith("http") and u not in seen:
                        seen.add(u)
                        urls.append(u)
            except Exception:
                continue
            if urls:
                break
        if urls:
            break
    return urls[:limit]


def _read_tg_channel(name: str, via_proxy: bool = None) -> str:
    """Read a public Telegram channel's preview page: through the active tunnel
    FIRST when one is up (t.me is filtered directly in regions like Iran),
    direct as a fallback. An explicit via_proxy tries only that one way (for
    callers that already know which side works)."""
    orders = [via_proxy] if via_proxy is not None else (
        [True, False] if _local_tunnel_up(refresh=0) else [False, True])
    for vp in orders:
        try:
            got = fetch_telegram_channel_configs(f"https://t.me/s/{name}", via_proxy=vp)
            if got:
                return got
        except Exception:
            continue
    return ""


def discover_web_sources(wanted: str, max_count: int, query: str = None) -> list:
    """Google-style whole-web discovery for free `wanted`-protocol configs. Runs live
    web searches, fetches the top result pages (t.me links are read as Telegram
    channel previews, and every fetched page is ALSO scanned for t.me channel links -
    so Telegram is searched through the web with no login at all), parses proxy
    links with _proxy_lines_from_text and returns them in the exact candidate shape
    every other source returns - so real sing-box verification, the FV quality gate,
    source memory and silent background pool-fill all apply unchanged. Domains that
    paid off before (namespace web:<proto> in discovered_sources.json) are re-tried
    first. Fully optional and silent: any error yields [] like an empty feed.
    `wanted` may be "any" (SW free text): then every supported protocol is accepted."""
    if not WEB_DISCOVERY_ENABLED:
        return []
    cache_key = f"{wanted}:{(query or '').strip()}"
    now = time.monotonic()
    hit = _WEB_DISCOVERY_CACHE.get(cache_key)
    if hit and now - hit[0] < WEB_DISCOVERY_CACHE_TTL:
        return hit[1]

    ns = f"web:{wanted}"
    q = (query or "").strip() or (
        _PROTOCOL_CANONICAL.get(wanted, wanted) if wanted != "any" else "free proxy config")
    queries = [
        f'"{q}" free config vless OR vmess OR trojan OR hysteria2',
        f'"{q}" free server subscription link',
        f'site:t.me/s "{q}" config',          # Telegram public channels, NO login
        f'"{q}" telegram channel free configs',
    ]

    urls, seen = [], set()
    for u, s in _DISCOVERY_MEMORY.summary(ns):       # known-good pages first
        if s > 0.35 and u not in seen:
            seen.add(u)
            urls.append(u)
    for qu in queries:
        for engine in (_ddg_search_urls, _searxng_search_urls):
            got = engine(qu, WEB_DISCOVERY_MAX_RESULTS)
            if got:
                for u in got:
                    if u not in seen:
                        seen.add(u)
                        urls.append(u)
                break

    lines, tg_names, tg_seen = [], [], set()
    limit = WEB_DISCOVERY_MAX_RESULTS + WEB_DISCOVERY_EXTRA_URL_SLOTS
    for u in urls[:limit]:
        text = ""
        try:
            m = re.match(r"https?://t\.me/(?:s/)?([A-Za-z0-9_]{4,})", u)
            if m:
                tg_names.append(m.group(1))
                continue                       # channel read below, counted separately
            _web_throttle()
            text = _fetch_page_text(u)
        except Exception:
            text = ""
        got = _proxy_lines_from_text(text)
        if got:
            lines.extend(got)
        _DISCOVERY_MEMORY.record(ns, u, bool(got))
        # Telegram half: any t.me channel link mentioned on this page is a
        # discovery lead - read its public preview too.
        for m in re.finditer(r'(?:https?://)?(?:www\.)?t\.me/(?:s/)?([A-Za-z0-9_]{4,})',
                             text or ""):
            name = m.group(1)
            if name not in tg_seen:
                tg_seen.add(name)
                tg_names.append(name)

    tg_ns = f"tgweb:{wanted}"
    remembered = [k for k, s in _DISCOVERY_MEMORY.summary(tg_ns) if s > 0.35]
    for name in remembered:                       # known-good channels first
        if name not in tg_seen:
            tg_seen.add(name)
            tg_names.insert(0, name)
    for name in tg_names[:WEB_DISCOVERY_MAX_TG_CHANNELS + len(remembered)]:
        got = _proxy_lines_from_text(_read_tg_channel(name))
        if got:
            lines.extend(got)
        _DISCOVERY_MEMORY.record(tg_ns, name, bool(got))

    if wanted == "any":                           # SW free text: accept all protocols
        plan, fps = [], set()
        for line in lines:
            try:
                ob = parse_proxy_uri(line, 0, extended=True)
            except Exception:
                ob = None
            if not ob:
                continue
            fp = _ob_fingerprint(ob)
            if fp in fps:
                continue
            fps.add(fp)
            ob["tag"] = f"PX-Web_Discovery-{ob.get('tag', '').lstrip()}".strip()
            plan.append(ob)
            if len(plan) >= max_count:
                break
    else:
        plan = _protocol_plan_from_lines(lines, wanted, max_count,
                                         tag_prefix="PX-Web_Discovery-")
    _WEB_DISCOVERY_CACHE[cache_key] = (now, plan)
    return plan


def search_web_free_text(binary: str, text: str):
    """SW free text ("works like Google"): search the whole web - INCLUDING
    Telegram via the web - for the typed words, verify every candidate with a
    real sing-box end-to-end request, and return the first healthy one in the
    exact (pool, manual_tag, src) shape search_protocol_server returns."""
    if not WEB_DISCOVERY_ENABLED:
        return None, None, None
    wait = FreeWaitDisplay(1, 50).start()
    stop_n = 0
    try:
        plan = discover_web_sources("any", WEB_DISCOVERY_FREETEXT_MAX, query=text)
        if not plan:
            return None, None, None
        wait.set_progress_total(len(plan))
        good, _bad = _quiet_verify(
            binary, plan, level=0, stop_after=1, workers=FV_PROTOCOL_WORKERS,
            deadline=time.monotonic() + FV_PROTOCOL_SOURCE_BUDGET, country=None,
            on_done=lambda ok: wait.tick(1))
        if good:
            found = [ob for ob, _ in good]
            stop_n = len(found)
            return found, found[0]["tag"], -1
        return None, None, None
    finally:
        wait.stop(stop_n)


_TUNNEL_UP_CACHE = [0.0, False]

def _local_tunnel_up(refresh: float = 5.0) -> bool:
    """True when the local mixed proxy (127.0.0.1:LOCAL_SOCKS_HTTP_PORT) actually
    carries traffic. Result cached a few seconds so hot paths stay cheap."""
    now = time.monotonic()
    if now - _TUNNEL_UP_CACHE[0] < refresh:
        return _TUNNEL_UP_CACHE[1]
    up = False
    try:
        req = urllib.request.Request("https://www.gstatic.com/generate_204", method="HEAD")
        with _proxied_opener(True).open(req, timeout=4) as r:
            up = r.status in (200, 204)
    except Exception:
        up = False
    _TUNNEL_UP_CACHE[0], _TUNNEL_UP_CACHE[1] = now, up
    return up

SW_CHANNEL_RECENT_POSTS = 50   # SW "@channel": always scan at least this many of the
# channel's most recent posts (see fetch_telegram_channel_recent_posts), not just
# whichever single page happens to have something first.


def _tg_channel_plan(channel: str, max_count: int, via_proxy: bool):
    """Read ONE named channel's last SW_CHANNEL_RECENT_POSTS posts and return
    (plan, raw_lines): verified-candidate-shaped outbounds, exactly like every other
    discovery source, plus the original config line behind each one (for saving to
    data/channel_<name>.txt before testing)."""
    text = fetch_telegram_channel_recent_posts(
        f"https://t.me/s/{channel}", via_proxy=via_proxy,
        target_posts=SW_CHANNEL_RECENT_POSTS) or ""
    plan, raw_lines, fps = [], [], set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ob = parse_proxy_uri(line, 0, extended=True)
        except Exception:
            ob = None
        if not ob:
            continue
        fp = _ob_fingerprint(ob)
        if fp in fps:
            continue
        fps.add(fp)
        raw_lines.append(line)
        ob["tag"] = f"PX-TG_@{channel}-{ob.get('tag', '').lstrip()}".strip()
        plan.append(ob)
        if len(plan) >= max_count:
            break
    return plan, raw_lines

def _tunnel_http_ping(timeout: int = 10):
    for url in ("https://www.gstatic.com/generate_204",
                "https://cp.cloudflare.com/generate_204"):
        t0 = time.monotonic()
        try:
            req = urllib.request.Request(url, method="HEAD")
            with _proxied_opener(True).open(req, timeout=timeout) as r:
                if r.status in (200, 204):
                    return (time.monotonic() - t0) * 1000.0
        except Exception:
            continue
    return None

def _direct_tcp_ping(host, port, timeout: int = 8, samples: int = 3):
    """TCP connect timing to the server's real address over NORMAL internet -
    the second half of the health check: after the VPN test, a direct-internet
    ping of the chosen server."""
    if not host or not port:
        return None
    best = None
    for _ in range(max(1, samples)):
        t0 = time.monotonic()
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                ms = (time.monotonic() - t0) * 1000.0
                best = ms if best is None else min(best, ms)
        except Exception:
            return None
    return best

def _dual_health_report(pool, label: str = ""):
    """Post-connect report: latency through the tunnel AND direct-internet health."""
    try:
        ob = pool[0] if pool else {}
        host, port = ob.get("server"), ob.get("server_port")
        v = _tunnel_http_ping()
        d = _direct_tcp_ping(host, port)
        vtxt = (f"{_C.GREEN}✓ VPN {_C.BOLD}{v:.0f} ms{_C.RESET}" if v is not None
                else f"{_C.RED}✗ VPN unreachable{_C.RESET}")
        if d is None:
            dtxt = f"{_C.ORANGE}⚠ Direct blocked (server only works via tunnel){_C.RESET}"
        else:
            dtxt = f"{_C.GREEN}✓ Direct {_C.BOLD}{d:.0f} ms{_C.RESET}"
        print(f"  {INFO} Health [{label}]:  {vtxt}   |   {dtxt}")
    except Exception:
        pass

_FILL_LOCK = threading.Lock()
_FILL_THREAD = None

def _silent_extra_protocol_fill(binary, target: int = SW_CHANNEL_SILENT_TARGET):
    """Silently search MORE protocols and merge their healthy servers into the
    active Switch Server pool. The user sees nothing (silent=True searches)."""
    pool = list(_state.get("free_verified_pool") or [])
    seen = {_ob_fingerprint(ob) for ob in pool}
    added = 0
    for proto in SW_CHANNEL_EXTRA_PROTOCOLS:
        if added >= target:
            break
        if proto not in _PROTOCOL_CANONICAL:
            continue
        try:
            found, _tag, _src = search_protocol_server(binary, proto, silent=True)
        except Exception:
            continue
        if not found:
            continue
        for ob in found:
            fp = _ob_fingerprint(ob)
            if fp in seen:
                continue
            seen.add(fp)
            pool.append(ob)
            added += 1
    _state["free_verified_pool"] = pool
    if pool:
        try:
            save_switch_server_pool(
                switch_server_cache_key(True, _state.get("free_source_index")), pool)
        except Exception:
            pass

def _silent_extra_protocol_fill_async(binary, target: int = SW_CHANNEL_SILENT_TARGET):
    global _FILL_THREAD
    with _FILL_LOCK:
        if _FILL_THREAD is not None and _FILL_THREAD.is_alive():
            return
        _FILL_THREAD = threading.Thread(target=_silent_extra_protocol_fill,
                                        args=(binary, target), daemon=True)
        _FILL_THREAD.start()

_SW_CHANNEL_TOKEN_RE = re.compile(r"^@([A-Za-z0-9_]{4,})$")
_SW_CHANNEL_LINK_RE = re.compile(r"^(?:https?://)?(?:www\.)?t\.me/(?:s/)?([A-Za-z0-9_]{4,})$", re.IGNORECASE)
_SW_PING_TOKEN_RE = re.compile(r"^[Pp](\d{1,5})$")


def _parse_sw_smart_query(raw: str):
    """Parse one free-form SW line into (channel, wanted, proto_name, country_code,
    country_name, ping_ms), or None when there is no @channel / t.me link in it
    (the caller then falls back to the plain whole-web search). The channel, a
    protocol name, a country name and a P<ping> code may appear in ANY order and
    any subset, e.g. all of these resolve the same way:
      @chan | @chan vless | @chan vless Germany | @chan vless Germany p400 |
      Vless @chan | @chan Germany Hysteria2 | p400 Germany vless @chan
    """
    words = (raw or "").split()
    if not words:
        return None
    channel = None
    rest = []
    for w in words:
        if channel is None:
            m = _SW_CHANNEL_TOKEN_RE.match(w) or _SW_CHANNEL_LINK_RE.match(w)
            if m:
                channel = m.group(1)
                continue
        rest.append(w)
    if channel is None:
        return None

    ping_ms = None
    remaining = []
    for w in rest:
        if ping_ms is None:
            m = _SW_PING_TOKEN_RE.match(w)
            if m:
                ping_ms = int(m.group(1))
                continue
        remaining.append(w)

    wanted = proto_name = country_code = country_name = None

    def _try_whole(text):
        pr = resolve_protocol(text)
        if pr:
            return pr, None
        cr = resolve_country(text)
        if cr:
            return None, cr
        return None, None

    if len(remaining) == 1:
        pr, cr = _try_whole(remaining[0])
        if pr:
            wanted, proto_name = pr
        elif cr:
            country_code, country_name = cr
    elif len(remaining) >= 2:
        for split_at in range(1, len(remaining)):
            left = " ".join(remaining[:split_at])
            right = " ".join(remaining[split_at:])
            lp, lc = resolve_protocol(left), resolve_country(right)
            rp, rc = resolve_protocol(right), resolve_country(left)
            if lp and lc:
                wanted, proto_name = lp
                country_code, country_name = lc
                break
            if rp and rc:
                wanted, proto_name = rp
                country_code, country_name = rc
                break
        if wanted is None and country_code is None:
            # the whole remainder might itself be one multi-word protocol
            # ("hysteria 2") or one multi-word country name on its own
            whole = " ".join(remaining)
            pr, cr = _try_whole(whole)
            if pr:
                wanted, proto_name = pr
            elif cr:
                country_code, country_name = cr

    return channel, wanted, proto_name, country_code, country_name, ping_ms


_SW_UDP_TOKEN_RE = re.compile(r"^udp$", re.IGNORECASE)
_SW_COUNT_TOKEN_RE = re.compile(r"^\d{1,3}$")


def _parse_sw_udp_count_query(raw: str):
    """SW line that contains the word 'udp' and/or a bare count number (1-999),
    combined in ANY order with an optional protocol, country, website or @channel:
      Vless udp | Germany udp | udp vless | udp (alone) | freeproxydb.com udp |
      @vpnjey udp | Vless 10 | Germany 6 | https://freeproxydb.com/ 8 |
      https://freeproxydb.com/ vless 6 | 6 https://freeproxydb.com/ vless
    Returns (channel, site_url, wanted, proto_name, country_code, country_name,
    want_udp, want_count), or None when the line has neither 'udp' nor a count
    (the caller then leaves the line for the existing SW handling, unchanged)."""
    words = (raw or "").split()
    if not words:
        return None
    want_udp = any(_SW_UDP_TOKEN_RE.match(w) for w in words)
    words = [w for w in words if not _SW_UDP_TOKEN_RE.match(w)]

    want_count = None
    if len(words) > 1:
        for i, w in enumerate(words):
            if _SW_COUNT_TOKEN_RE.match(w):
                want_count = int(w)
                del words[i]           # remove exactly this one token, keep the rest in order
                break

    if not want_udp and want_count is None:
        return None

    channel = None
    site_url = None
    remaining = []
    for w in words:
        if channel is None:
            m = _SW_CHANNEL_TOKEN_RE.match(w) or _SW_CHANNEL_LINK_RE.match(w)
            if m:
                channel = m.group(1)
                continue
        if site_url is None:
            su = _parse_sw_site_query(w)
            if su:
                site_url = su
                continue
        remaining.append(w)

    wanted = proto_name = country_code = country_name = None

    def _try_whole(text):
        pr = resolve_protocol(text)
        if pr:
            return pr, None
        cr = resolve_country(text)
        if cr:
            return None, cr
        return None, None

    if len(remaining) == 1:
        pr, cr = _try_whole(remaining[0])
        if pr:
            wanted, proto_name = pr
        elif cr:
            country_code, country_name = cr
    elif len(remaining) >= 2:
        whole = " ".join(remaining)
        pr, cr = _try_whole(whole)
        if pr:
            wanted, proto_name = pr
        elif cr:
            country_code, country_name = cr
        else:
            for split_at in range(1, len(remaining)):
                left, right = " ".join(remaining[:split_at]), " ".join(remaining[split_at:])
                lp, lc = resolve_protocol(left), resolve_country(right)
                rp, rc = resolve_protocol(right), resolve_country(left)
                if lp and lc:
                    wanted, proto_name = lp
                    country_code, country_name = lc
                    break
                if rp and rc:
                    wanted, proto_name = rp
                    country_code, country_name = rc
                    break

    return channel, site_url, wanted, proto_name, country_code, country_name, want_udp, want_count


# ---- Security gate for searched (free / public) servers -----------------------------
# A searched server is only accepted when its real EXIT IP reports ISP and Org info
# (the same "ISP" / "Org" rows shown in the connection box). Missing info = not accepted
# and the next candidate is tried; if none pass, the previous connection is kept.
SEARCH_REQUIRE_ISP_ORG = True
SEARCH_ISP_ORG_REQUIRE_BOTH = False  # True: ISP *and* Org must exist. False: either one is enough.
_ISP_ORG_EMPTY = (None, "", "?", "unknown", "n/a", "none", "null")


def _has_isp_org_value(v) -> bool:
    return str(v).strip().lower() not in _ISP_ORG_EMPTY if v is not None else False


def _exit_has_isp_org(tries: int = 3) -> bool:
    """Ask the IP-info service THROUGH the tunnel who owns the exit IP."""
    for attempt in range(max(1, tries)):
        info = fetch_public_ip_info()
        if isinstance(info, dict) and "error" not in info:
            has_isp = _has_isp_org_value(info.get("isp"))
            has_org = _has_isp_org_value(info.get("org"))
            return (has_isp and has_org) if SEARCH_ISP_ORG_REQUIRE_BOTH else (has_isp or has_org)
        time.sleep(1)
    return False


def _requires_isp_org(fn):
    """Decorator for every connect_by_* search: while it runs, servers without ISP/Org
    info on their exit IP are rejected inside _connect_trying_tags."""
    import functools

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        prev = _state.get("require_isp_org")
        _state["require_isp_org"] = bool(SEARCH_REQUIRE_ISP_ORG)
        try:
            return fn(*args, **kwargs)
        finally:
            _state["require_isp_org"] = prev
    return wrapper


@_requires_isp_org
def connect_by_telegram_channel_filtered(binary: str, channel: str, wanted: str = None,
                                         proto_name: str = None, country_code: str = None,
                                         country_name: str = None, ping_ms: int = None,
                                         want_udp: bool = False, want_count: int = None):
    """SW '@channel [protocol] [country] [pPING]' in any order: read that named
    channel - through the active tunnel FIRST when one is up, direct fallback
    (t.me is filtered directly in regions like Iran) - keep only the configs
    that match the requested protocol/country/ping (when given), verify with
    real sing-box requests and connect to the first healthy match. With no
    filters at all this behaves exactly like the plain '@channel' search."""
    channel = re.sub(r"^(?:https?://)?(?:www\.)?t\.me/(?:s/)?|@", "", (channel or "").strip())
    if not re.fullmatch(r"[A-Za-z0-9_]{4,}", channel or ""):
        print(f"{FAIL} Invalid channel name: @{channel}")
        return "none", None

    # 1) channel through the tunnel FIRST when one is up, direct fallback
    order = [True, False] if _local_tunnel_up(refresh=0) else [False, True]
    plan, raw_lines = [], []
    for vp in order:
        try:
            plan, raw_lines = _tg_channel_plan(channel, SW_CHANNEL_MAX_CANDIDATES, via_proxy=vp)
        except Exception:
            plan, raw_lines = [], []
        if plan:
            break
    if not plan and not _local_tunnel_up(refresh=0):
        # 2) bootstrap: t.me is filtered and nothing is connected yet - get ANY
        #    healthy server via the normal web path, then read the channel via it
        print(f"{INFO} No tunnel yet - bootstrapping a server to reach t.me ...")
        b_status, _b = connect_by_web_text(binary, "vless free config")
        if b_status == "ok" and _local_tunnel_up(refresh=0):
            plan, raw_lines = _tg_channel_plan(channel, SW_CHANNEL_MAX_CANDIDATES, via_proxy=True)
    if not plan:
        old_saved = _channel_load_saved(channel)
        if old_saved:
            print(f"{WARN} @{channel} could not be read - using the list saved earlier ({len(old_saved)})")
            plan = _channel_plan_from_saved(channel, old_saved, SW_CHANNEL_MAX_CANDIDATES)
            raw_lines = old_saved
    if not plan:
        print(f"{FAIL} No configs found in @{channel} (empty/private/unreachable)")
        return "none", None

    # 2b) SAVE every config found - BEFORE any health testing - to
    #     data/channel_<name>.txt (a new numbered file per search, same as SW "website").
    path = _channel_save_file(channel, raw_lines)
    if path:
        print(f"{OK} @{channel}: {len(raw_lines)} configs saved -> {os.path.relpath(path)}")

    # 3) narrow to the requested protocol before spending real verification
    #    time on configs that could never match anyway
    if wanted:
        plan = [ob for ob in plan if _protocol_match(ob, wanted)]
        if not plan:
            print(f"{FAIL} @{channel} has configs, but none are {proto_name}")
            return "none", None
    elif want_udp:
        plan = [ob for ob in plan if str(ob.get("type")) in UDP_CAPABLE_PROTOCOLS]
        if not plan:
            print(f"{FAIL} @{channel} has configs, but none support UDP")
            return "none", None

    # 4) verify with real end-to-end sing-box requests, exactly like every
    #    other search; a country filter is checked for real (actual exit IP -
    #    see _verify_one_fv_sublink/want_country), a ping filter needs every
    #    candidate tested so the fastest matching one can be picked
    upper_ms = ping_search_upper_bound(ping_ms) if ping_ms else None
    wait = FreeWaitDisplay(1, 50).start()
    good = []
    try:
        wait.set_progress_total(len(plan))
        good, _bad = _quiet_verify(
            binary, plan, level=0,
            stop_after=(want_count if want_count else (1 if upper_ms is None else None)),
            workers=FV_PROTOCOL_WORKERS,
            deadline=time.monotonic() + FV_PROTOCOL_SOURCE_BUDGET,
            country=country_code, on_done=lambda ok: wait.tick(1), want_udp=want_udp)
    finally:
        wait.stop(1 if good else 0)

    if upper_ms is not None:
        good = [(ob, d) for ob, d in good if d is not None and 0 < float(d) <= upper_ms]

    if not good:
        bits = []
        if proto_name: bits.append(proto_name)
        if country_name: bits.append(f"in {country_name}")
        if ping_ms: bits.append(f"under {upper_ms} ms")
        why = " ".join(bits) or "verification"
        print(f"{FAIL} @{channel}: no server matched {why}")
        return "failed", None

    # 5) connect - mirrors connect_by_telegram_channel / connect_by_web_text
    pool = [ob for ob, _ in good]
    kill_singbox()
    _state["cleaned_up"] = False
    prev = (_state.get("free_vless_mode"), _state.get("free_source_index"),
            _state.get("free_verified_pool"))
    _state["free_vless_mode"] = True
    _state["free_source_index"] = -1  # sentinel: NOT a real T<n> source (avoids colliding with the actual last source, T29)
    _state["free_verified_pool"] = pool[:FREE_VLESS_COUNT]
    label_bits = [f"@{channel}"]
    if proto_name: label_bits.append(proto_name)
    if country_name: label_bits.append(country_name)
    proc, tag, ok = connect_with_fallback(binary, pool, pool[0]["tag"], False, pool,
                                          label=f"TG 📢 {' '.join(label_bits)}", enable_fragment=None)
    if tag and ok:
        save_switch_server_pool(switch_server_cache_key(True, -1), pool)
        _dual_health_report(pool, " ".join(label_bits))
        if not (wanted or country_code or ping_ms or want_udp or want_count):
            _silent_extra_protocol_fill_async(binary)   # plain @channel only
        elif _RESERVE is not None and (want_udp or want_count):
            rest = [ob for ob in plan if ob["tag"] not in {o["tag"] for o in pool}]
            _RESERVE.set_site_feed(rest, f"TG @{channel}", enough=want_count, hard_cap=want_count)
            _RESERVE.udp_only = want_udp
        return "ok", (proc, tag, True, pool, pool[0]["tag"], -1)
    _state["free_vless_mode"], _state["free_source_index"], _state["free_verified_pool"] = prev
    kill_singbox()
    _state["cleaned_up"] = False
    return "failed", None


@_requires_isp_org
def connect_by_telegram_channel(binary: str, channel: str):
    """SW '@Argo_vpn1': read that NAMED channel through the tunnel, verify its
    configs with real sing-box requests, connect to the first healthy one, then
    silently find 8-10 more healthy protocol servers in the background."""
    channel = re.sub(r"^(?:https?://)?(?:www\.)?t\.me/(?:s/)?|@", "", (channel or "").strip())
    if not re.fullmatch(r"[A-Za-z0-9_]{4,}", channel or ""):
        print(f"{FAIL} Invalid channel name: @{channel}")
        return "none", None

    # 1) channel through the tunnel when one is up; direct fallback otherwise
    plan, raw_lines = _tg_channel_plan(channel, SW_CHANNEL_MAX_CANDIDATES, via_proxy=_local_tunnel_up())
    if not plan and not _local_tunnel_up(refresh=0):
        # 2) bootstrap: t.me is filtered and nothing is connected yet - get ANY
        #    healthy server via the normal web path, then read the channel via it
        print(f"{INFO} No tunnel yet - bootstrapping a server to reach t.me ...")
        b_status, _b = connect_by_web_text(binary, "vless free config")
        if b_status == "ok" and _local_tunnel_up(refresh=0):
            plan, raw_lines = _tg_channel_plan(channel, SW_CHANNEL_MAX_CANDIDATES, via_proxy=True)
    if not plan:
        old_saved = _channel_load_saved(channel)
        if old_saved:
            print(f"{WARN} @{channel} could not be read - using the list saved earlier ({len(old_saved)})")
            plan = _channel_plan_from_saved(channel, old_saved, SW_CHANNEL_MAX_CANDIDATES)
            raw_lines = old_saved
    if not plan:
        print(f"{FAIL} No configs found in @{channel} (empty/private/unreachable)")
        return "none", None

    # 2b) SAVE every config found - BEFORE any health testing - to
    #     data/channel_<name>.txt (a new numbered file per search, same as SW "website").
    path = _channel_save_file(channel, raw_lines)
    if path:
        print(f"{OK} @{channel}: {len(raw_lines)} configs saved -> {os.path.relpath(path)}")

    # 3) verify with real end-to-end sing-box requests, exactly like every search
    wait = FreeWaitDisplay(1, 50).start()
    good = []
    try:
        wait.set_progress_total(len(plan))
        good, _bad = _quiet_verify(binary, plan, level=0, stop_after=1,
                                   workers=FV_PROTOCOL_WORKERS,
                                   deadline=time.monotonic() + FV_PROTOCOL_SOURCE_BUDGET,
                                   country=None, on_done=lambda ok: wait.tick(1))
    finally:
        wait.stop(1 if good else 0)
    if not good:
        print(f"{FAIL} @{channel} had configs but none passed verification")
        return "failed", None

    # 4) connect - mirrors connect_by_web_text state handling
    pool = [ob for ob, _ in good]
    kill_singbox()
    _state["cleaned_up"] = False
    prev = (_state.get("free_vless_mode"), _state.get("free_source_index"),
            _state.get("free_verified_pool"))
    _state["free_vless_mode"] = True
    _state["free_source_index"] = -1  # sentinel: NOT a real T<n> source (avoids colliding with the actual last source, T29)
    _state["free_verified_pool"] = pool[:FREE_VLESS_COUNT]
    proc, tag, ok = connect_with_fallback(binary, pool, pool[0]["tag"], False, pool,
                                          label=f"TG 📢 @{channel}", enable_fragment=None)
    if tag and ok:
        save_switch_server_pool(switch_server_cache_key(True, -1), pool)
        _dual_health_report(pool, f"@{channel}")
        _silent_extra_protocol_fill_async(binary)   # 8-10 more protocols, hidden
        return "ok", (proc, tag, True, pool, pool[0]["tag"], -1)
    _state["free_vless_mode"], _state["free_source_index"], _state["free_verified_pool"] = prev
    kill_singbox()
    _state["cleaned_up"] = False
    return "failed", None

@_requires_isp_org
def connect_by_web_text(binary: str, text: str):
    """Connect to the FIRST healthy server found by an SW free-text web search.
    Mirrors connect_by_protocol so FV state, reserve pool-fill and Switch Server
    keep working exactly like every other search."""
    pool, manual, src = search_web_free_text(binary, text)
    if not pool:
        return "none", None
    kill_singbox()
    _state["cleaned_up"] = False
    prev = (_state.get("free_vless_mode"), _state.get("free_source_index"),
            _state.get("free_verified_pool"))
    _state["free_vless_mode"] = True
    _state["free_source_index"] = -1  # sentinel: NOT a real T<n> source (avoids colliding with the actual last source, T29)
    _state["free_verified_pool"] = pool[:FREE_VLESS_COUNT]
    proc, tag, ok = connect_with_fallback(binary, pool, manual, False, pool,
                                          label=f"Web 🔍 {text[:30]}", enable_fragment=None)
    if tag and ok:
        save_switch_server_pool(switch_server_cache_key(True, src), pool)
        _dual_health_report(pool, f"Web 🔍 {text[:30]}")
        return "ok", (proc, tag, True, pool, manual or tag, src)
    _state["free_vless_mode"], _state["free_source_index"], _state["free_verified_pool"] = prev
    kill_singbox()
    _state["cleaned_up"] = False
    return "failed", None


# ============================================================================
# SW "website": search ONE named site (freeproxydb.com / https://freeproxydb.com/)
# ============================================================================
# Typing a site name or URL after SW does this, in order:
#   1) CRAWL the site (through the VPN first when one is up - the site itself may be
#      filtered - direct as a fallback; with no tunnel and a blocked site a helper
#      server is bootstrapped first, exactly like SW "@channel"). Plain page scraping
#      is not enough for modern sites: their proxy tables are filled in by JavaScript
#      from a JSON/text API. So the crawler also reads the site's scripts and API
#      documentation, finds the list/subscribe endpoints and pages through them.
#   2) SAVE every protocol found (up to SITE_TARGET_CANDIDATES) to
#      data/site_<host>.txt - one link per line, importable as a subscription file.
#   3) TEST them on the NORMAL internet (temporary sing-box processes) and
#      connect to the FIRST healthy one.
#   4) Silently keep testing the rest in the background (ReserveManager site feed) until
#      6-10 healthy servers are stored: "Switch Server : 1 - N" then shows only servers
#      of THIS site, so the user can jump between them.
SITE_SEARCH_ENABLED = True
SITE_TARGET_CANDIDATES = 300          # protocols kept from the site (and saved to the file)
SITE_CRAWL_MAX_PAGES = 45             # pages fetched per site
SITE_CRAWL_MAX_JS = 8                 # script files read to find the site's API
SITE_CRAWL_MAX_API_CALLS = 30         # API requests per site (list/subscribe endpoints)
SITE_CRAWL_TIME_BUDGET = 100.0        # seconds for the whole crawl
SITE_CRAWL_REQUEST_GAP = 0.8          # be polite: minimum seconds between requests to the site
SITE_CRAWL_TIMEOUT = 20               # seconds per request
SITE_CRAWL_MAX_BYTES = 3_000_000      # bytes read from one response
SITE_SHARE_MIN = 40                   # fewer share links than this -> also ask for socks/http lists
SITE_VERIFY_BUDGET = 240.0            # seconds spent testing the found protocols
SITE_VERIFY_WORKERS = FV_PROTOCOL_WORKERS
SITE_FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
SITE_API_SHARE_PROTOCOLS = "vless,vmess,trojan,hysteria2,ss"
SITE_API_CLASSIC_PROTOCOLS = "socks5,socks4,http"
SITE_WELL_KNOWN_API_PATHS = (         # tried only when the crawl found no API by itself
    "/api/proxy/search", "/api/proxy/subscribe", "/api/proxies", "/api/v1/proxies",
    "/api/subscribe", "/subscribe", "/sub",
)
FV_SITE_RESERVE_WORKERS = 4           # background tests at once while filling Switch Server from a site
FV_SITE_RESERVE_BUDGET = 600.0        # seconds the background fill may use on one site list (it also stops as soon as SITE_SWITCH_MAX is reached)
SITE_SWITCH_MAX = 15                  # Switch Server holds up to this many healthy servers of ONE searched site (the connected one included); the background test stops here
SITE_SWITCH_REFRESH_GAP = 20.0        # while the site list is being tested: redraw "Switch Server : 1 - N" at most this often
SITE_FILE_MAX_AGE_DAYS = 5            # data/site_*.txt files older than this are deleted
SITE_FILE_CLEANUP_EVERY = 3600.0      # ...checked at most once per hour while the program runs

_SITE_HOST_RE = re.compile(
    r"^(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?::\d{1,5})?(?:[/?#]\S*)?$",
    re.IGNORECASE)
_SITE_BLOCKED_HOSTS = ("t.me", "telegram.me", "telegram.dog", "telegram.org", "telesco.pe")
_SITE_ASSET_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".woff",
                   ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".webm", ".pdf", ".zip",
                   ".gz", ".map", ".apk", ".exe")
_SITE_KEY_TOKENS = {
    "proxy", "proxies", "freeproxy", "vless", "vmess", "trojan", "hysteria", "hysteria2", "hy2",
    "shadowsocks", "ss", "ssr", "v2ray", "xray", "clash", "singbox", "config", "configs", "sub",
    "subscribe", "subscription", "free", "list", "node", "nodes", "server", "servers", "vpn",
    "export", "download", "raw", "country", "protocol", "telegram", "tuic", "socks", "socks5",
    "http", "mtproto",
}
_SITE_DOC_TOKENS = {"doc", "docs", "documentation", "api", "guide", "swagger", "openapi", "developer"}
_SITE_EP_GOOD = {"search", "list", "proxies", "proxy", "subscribe", "sub", "subscription", "export",
                 "feed", "configs", "config", "nodes", "servers", "free", "valid"}
_SITE_EP_BAD = {"crawler", "checker", "check", "client", "statistics", "stats", "login", "logout",
                "register", "signup", "auth", "oauth", "token", "admin", "user", "users", "payment",
                "checkout", "order", "billing", "upload", "delete", "captcha", "contact",
                "feedback", "track", "analytics", "anon", "geoip", "whois"}
_SITE_FEED_TOKENS = {"subscribe", "sub", "subscription", "feed", "export", "download"}

_SITE_URI_RE = re.compile(
    r"(?<![A-Za-z0-9+.\-_])"
    r"(?:vless|vmess|trojan|hysteria2|hysteria|hy2|hy|tuic|ss|shadowtls|anytls|"
    r"naive\+https|naive\+quic|naive|wireguard|warp|snell|ssh|"
    r"socks5h|socks5|socks4a|socks4|socks|https|http)"
    r"://[^\s\"'<>`\\]+", re.IGNORECASE)
# socks:// is unambiguous; http(s):// is only a PROXY when it is a bare ip:port (every
# other http link on a page is just a link).
_SITE_SOCKS_RE = re.compile(r"^socks\w*://(?:[^/@\s]+@)?[^/\s:@]+:\d{2,5}/?(?:#.*)?$", re.IGNORECASE)
_SITE_HTTP_PROXY_RE = re.compile(
    r"^https?://(?:[^/@\s]+@)?(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]):\d{2,5}/?(?:#.*)?$",
    re.IGNORECASE)
_SITE_CF_EMAIL_RE = re.compile(
    r'<(?:a|span)\b[^>]*?data-cfemail="([0-9a-fA-F]{6,})"[^>]*>.*?</(?:a|span)>', re.S)
_SITE_LINK_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"'\s>]+)["']""", re.IGNORECASE)
_SITE_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
_SITE_ENDPOINT_RE = re.compile(
    r"(?:https?://[A-Za-z0-9.\-]+(?::\d+)?)?/(?:api|v\d{1,2})/[A-Za-z0-9_\-./]*[A-Za-z0-9_]",
    re.IGNORECASE)
_SITE_ENDPOINT2_RE = re.compile(
    r"""["'`](/[A-Za-z0-9_\-/]{0,120}(?:subscribe|subscription|search|export|proxies|proxy-list|"""
    r"""proxy_list|configs?|nodes)[A-Za-z0-9_\-/]{0,120})["'`]""", re.IGNORECASE)
_SITE_JSCHUNK_RE = re.compile(r"""["'](?:\./)?([A-Za-z0-9_\-./]+\.m?js)["']""")


def _parse_sw_site_query(raw: str):
    """SW input -> normalised site URL, or None when the line is not a website.

    Accepts  freeproxydb.com | www.freeproxydb.com | https://freeproxydb.com/ |
    https://site.tld/some/page?x=1 ; Telegram links (t.me/...) are NOT sites (they
    belong to the @channel search) and a bare protocol/country word never has a dot.
    """
    text = (raw or "").strip()
    if not text or any(c.isspace() for c in text) or "@" in text:
        return None
    m = _SITE_HOST_RE.match(text)
    if not m:
        return None
    host = m.group(1).lower()
    if any(host == b or host.endswith("." + b) for b in _SITE_BLOCKED_HOSTS):
        return None
    url = text if re.match(r"^https?://", text, re.IGNORECASE) else "https://" + text
    p = urllib.parse.urlsplit(url)
    if not p.netloc:
        return None
    return urllib.parse.urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))


def _site_same(url_host: str, base: str) -> bool:
    h = re.sub(r"^www\.", "", (url_host or "").split(":")[0].lower())
    return h == base or h.endswith("." + base)


def _site_cf_decode(m) -> str:
    """Cloudflare 'email protection' rewrites anything shaped like user@host - which is
    exactly what vless://uuid@server:443 looks like - into a hex blob. Undo it."""
    try:
        h = m.group(1)
        key = int(h[:2], 16)
        return "".join(chr(int(h[i:i + 2], 16) ^ key) for i in range(2, len(h) - 1, 2))
    except Exception:
        return m.group(0)


def _site_prepare_text(text: str) -> str:
    t = text
    if "data-cfemail" in t:
        t = _SITE_CF_EMAIL_RE.sub(_site_cf_decode, t)
    if "\\" in t:   # JSON-escaped links: vless:\/\/...\u0026...
        t = t.replace("\\/", "/")
        t = re.sub(r"\\u00([0-7][0-9a-fA-F])", lambda m: chr(int(m.group(1), 16)), t)
    return html_lib.unescape(t)


def _site_try_base64(text: str) -> str:
    s = re.sub(r"\s+", "", (text or "").strip())
    if len(s) < 100 or not re.fullmatch(r"[A-Za-z0-9+/_\-]+={0,2}", s):
        return ""
    try:
        s = s.replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _site_extract(text: str, _depth: int = 0) -> list:
    """Every real proxy link in one fetched body (HTML, JSON, plain list or a base64
    subscription): share links (vless/vmess/trojan/...) plus socks:// and http://ip:port.
    Ordinary web links are never mistaken for proxies."""
    if not text:
        return []
    body = _site_prepare_text(text)
    out, seen = [], set()
    for m in _SITE_URI_RE.finditer(body):
        uri = m.group(0).rstrip("`).,;]}\\")
        scheme = uri.split("://", 1)[0].lower()
        if scheme in ("http", "https"):
            if not _SITE_HTTP_PROXY_RE.match(uri):
                continue
        elif scheme.startswith("socks"):
            if not _SITE_SOCKS_RE.match(uri):
                continue
        if len(uri) < 12 or len(uri) > 4000 or uri in seen:
            continue
        seen.add(uri)
        out.append(uri)
    if not out and _depth == 0:
        blob = _site_try_base64(text)
        if blob:
            return _site_extract(blob, _depth=1)
    return out


def _site_group(uri: str) -> int:
    """0 = share links (vless/vmess/...), 1 = socks, 2 = plain http proxies (tested last)."""
    scheme = uri.split("://", 1)[0].lower()
    if scheme in ("http", "https"):
        return 2
    return 1 if scheme.startswith("socks") else 0


def _site_link_score(url: str) -> int:
    p = urllib.parse.urlsplit(url)
    path = p.path.lower()
    if path.endswith(_SITE_ASSET_EXT) or "/cdn-cgi/" in path:
        return -1
    toks = [t for t in re.split(r"[^a-z0-9]+", path + " " + p.query.lower()) if t]
    s = sum(2 for t in toks if t in _SITE_KEY_TOKENS)
    if path.endswith((".txt", ".json", ".csv", ".yaml", ".yml", ".list", ".conf", ".sub", ".xml")):
        s += 3
    if any(t in _SITE_DOC_TOKENS for t in toks):
        s += 3
    if re.search(r"(?:^|[?&])(?:page|p|offset|start)=\d+", p.query):
        s += 1
    return s


def _site_find_links(text: str, page_url: str, base: str):
    """(pages, scripts): same-site links worth following (with their score) and the
    site's own script files (where SPAs keep their API paths)."""
    pages, scripts, seen = [], [], set()
    for m in _SITE_LINK_RE.finditer(_site_prepare_text(text)):
        raw = m.group(1).strip()
        if raw.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
            continue
        try:
            u = urllib.parse.urljoin(page_url, raw)
            p = urllib.parse.urlsplit(u)
        except Exception:
            continue
        if p.scheme not in ("http", "https") or not _site_same(p.netloc, base):
            continue
        u = urllib.parse.urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))
        if u in seen:
            continue
        seen.add(u)
        if p.path.lower().endswith((".js", ".mjs")):
            scripts.append(u)
        else:
            sc = _site_link_score(u)
            if sc >= 2:
                pages.append((u, sc))
    return pages, scripts


def _site_endpoint_ok(url: str) -> bool:
    p = urllib.parse.urlsplit(url)
    toks = {t for t in re.split(r"[^a-z0-9]+", p.path.lower()) if t}
    return bool(toks & _SITE_EP_GOOD) and not (toks & _SITE_EP_BAD)


def _site_is_feed(ep: str) -> bool:
    toks = {t for t in re.split(r"[^a-z0-9]+", urllib.parse.urlsplit(ep).path.lower()) if t}
    return bool(toks & _SITE_FEED_TOKENS)


def _site_find_endpoints(text: str, origin: str, base: str) -> list:
    """API endpoints that look like a proxy list / subscription (GET only), found in
    HTML, API documentation and JavaScript."""
    body = _site_prepare_text(text)
    found, seen = [], set()
    cands = [m.group(0) for m in _SITE_ENDPOINT_RE.finditer(body)]
    cands += [m.group(1) for m in _SITE_ENDPOINT2_RE.finditer(body)]
    for c in cands:
        try:
            u = urllib.parse.urljoin(origin + "/", c)
            p = urllib.parse.urlsplit(u)
        except Exception:
            continue
        if p.scheme not in ("http", "https") or not _site_same(p.netloc, base):
            continue
        u = urllib.parse.urlunsplit((p.scheme, p.netloc, p.path.rstrip("/"), "", ""))
        if u in seen or not _site_endpoint_ok(u):
            continue
        seen.add(u)
        found.append(u)
    return found


class _SiteFetcher:
    """One polite HTTP client for ONE site. Learns whether the site is reachable through
    the tunnel or directly, spaces its requests out, and understands rate limits."""

    def __init__(self, deadline: float):
        self.deadline = deadline
        self.route = None                       # True = via tunnel, False = direct (learned)
        self._tunnel = _local_tunnel_up(refresh=0)
        self._last = 0.0
        self.calls = 0
        self.retry_after = None

    def expired(self) -> bool:
        return time.monotonic() > self.deadline

    def get(self, url: str, timeout: float = None, max_bytes: int = None):
        """-> (status, text, content_type); status None = unreachable."""
        from urllib.error import HTTPError
        if self.expired():
            return None, "", ""
        if self.route is not None:
            orders = [self.route, not self.route]
        else:
            orders = [True, False] if self._tunnel else [False, True]
        first_err = None
        for via in orders:
            wait = SITE_CRAWL_REQUEST_GAP - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            self.calls += 1
            try:
                req = urllib.request.Request(url, headers={
                    "User-Agent": _WEB_SEARCH_UA,
                    "Accept": "text/html,application/json,text/plain,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.8",
                    "Accept-Encoding": "identity"})
                with _proxied_opener(via).open(req, timeout=timeout or SITE_CRAWL_TIMEOUT) as resp:
                    raw = resp.read(max_bytes or SITE_CRAWL_MAX_BYTES)
                    ctype = resp.headers.get("Content-Type", "") or ""
                    enc = (resp.headers.get("Content-Encoding") or "").lower()
                    try:
                        charset = resp.headers.get_content_charset() or "utf-8"
                    except Exception:
                        charset = "utf-8"
                    status = resp.status
                if enc in ("gzip", "x-gzip"):
                    raw = gzip.decompress(raw)
                elif enc == "deflate":
                    raw = zlib.decompress(raw)
                try:
                    text = raw.decode(charset, errors="ignore")
                except LookupError:
                    text = raw.decode("utf-8", errors="ignore")
                self.route = via
                return status, text, ctype
            except HTTPError as e:
                body = ""
                try:
                    body = e.read(200_000).decode("utf-8", errors="ignore")
                except Exception:
                    pass
                try:
                    self.retry_after = e.headers.get("Retry-After")
                except Exception:
                    self.retry_after = None
                if e.code in (403, 429, 503) and via is orders[0] and len(orders) > 1:
                    first_err = (e.code, body)     # blocked/limited on this route: the
                    continue                        # other route has a different IP
                if first_err is None:
                    self.route = via
                    first_err = (e.code, body)
                return first_err[0], first_err[1], ""
            except Exception:
                continue
        if first_err is not None:
            return first_err[0], first_err[1], ""
        return None, "", ""


def _site_api_variants(kind: str, protos: str):
    """Request parameter sets to try against an unknown list/subscribe endpoint, most
    specific first (unknown parameters are ignored by most servers; a strict server
    answers 400 and the next set is tried). -> (builders, paginated)."""
    if kind == "feed":
        return [
            lambda p: {"count": 500, "subscribe_format": "original", "protocol": protos},
            lambda p: {"count": 100, "subscribe_format": "original", "protocol": protos},
            lambda p: {"count": 100, "protocol": protos},
            lambda p: {},
        ], False
    return [
        lambda p: {"page_size": 100, "page_index": p, "protocol": protos,
                   "order_by": "check_success_count", "order_dir": "desc",
                   "fields": "connect_string"},
        lambda p: {"page_size": 100, "page_index": p, "protocol": protos,
                   "order_by": "check_success_count", "order_dir": "desc"},
        lambda p: {"page_size": 100, "page_index": p, "protocol": protos},
        lambda p: {"limit": 100, "page": p, "protocol": protos},
        lambda p: {"per_page": 100, "page": p},
        lambda p: {},
    ], True


def crawl_site_for_proxies(site_url: str, target: int = None, progress=None):
    """Crawl one website and return (uris, info): up to `target` proxy links, share links
    first (vless/vmess/trojan/...), then socks, then http. See the block comment above
    for what 'crawl' includes (pages, scripts, API docs, list/subscribe endpoints)."""
    import heapq
    target = int(target or SITE_TARGET_CANDIDATES)
    want_raw = int(target * 1.25)          # a few links will not parse: collect a bit extra
    parts = urllib.parse.urlsplit(site_url)
    host = parts.netloc.lower()
    origin = f"{parts.scheme}://{parts.netloc}"
    base = re.sub(r"^www\.", "", host.split(":")[0])
    fetcher = _SiteFetcher(time.monotonic() + SITE_CRAWL_TIME_BUDGET)

    uris, useen = [], set()
    stats = {"pages": 0, "api": 0, "endpoints": 0, "hits": 0, "route": None}

    def add(items) -> int:
        n = 0
        for u in items:
            if u not in useen:
                useen.add(u)
                uris.append(u)
                n += 1
        return n

    heap, queued, order = [], set(), [0]
    js_q, js_seen = [], set()
    ep_q, ep_seen = [], set()
    page_hashes = set()

    def push_page(url, score, depth):
        if url in queued or depth > 3:
            return
        queued.add(url)
        order[0] += 1
        heapq.heappush(heap, (-score, order[0], depth, url))

    def note_progress():
        if progress is not None:
            try:
                progress()
            except Exception:
                pass

    def handle(url, text, depth, is_js=False):
        add(_site_extract(text))
        for ep in _site_find_endpoints(text, origin, base):
            if ep not in ep_seen:
                ep_seen.add(ep)
                ep_q.append(ep)
        if is_js:   # lazily loaded chunks are where SPAs keep their API paths
            for m in _SITE_JSCHUNK_RE.finditer(text):
                try:
                    u = urllib.parse.urljoin(url, m.group(1))
                    p = urllib.parse.urlsplit(u)
                except Exception:
                    continue
                if _site_same(p.netloc, base) and u not in js_seen and u not in js_q:
                    js_q.append(u)
            return
        if "<urlset" in text[:2000] or "<sitemapindex" in text[:2000]:
            for m in _SITE_LOC_RE.finditer(text):
                u = html_lib.unescape(m.group(1))
                p = urllib.parse.urlsplit(u)
                if _site_same(p.netloc, base):
                    sc = _site_link_score(u)
                    if sc >= 2 or u.lower().endswith(".xml"):
                        push_page(u, max(sc, 2), depth + 1)
            return
        h = hash(text[:20000])
        if h in page_hashes:                # same SPA shell served for every route
            return
        page_hashes.add(h)
        pages, scripts = _site_find_links(text, url, base)
        for u, sc in pages:
            push_page(u, sc, depth + 1)
        for s in scripts:
            if s not in js_seen and s not in js_q:
                js_q.append(s)

    def call_api(ep, params):
        q = urllib.parse.urlencode(params, safe=",")
        url = f"{ep}?{q}" if q else ep
        st, text, _ct = fetcher.get(url)
        stats["api"] += 1
        note_progress()
        if st == 429:                       # rate limited: honour Retry-After once
            try:
                wait = min(float(fetcher.retry_after or 8), 15.0)
            except Exception:
                wait = 8.0
            if not fetcher.expired():
                time.sleep(wait)
                st, text, _ct = fetcher.get(url)
                stats["api"] += 1
        return st, text

    def pull_endpoint(ep, probe: bool = False):
        kind = "feed" if _site_is_feed(ep) else "search"
        groups = [SITE_API_SHARE_PROTOCOLS, SITE_API_CLASSIC_PROTOCOLS]
        got_here = False
        for gi, protos in enumerate(groups):
            if gi == 1 and len(uris) >= SITE_SHARE_MIN:
                break                       # enough share links: skip the socks/http lists
            if len(uris) >= want_raw or stats["api"] >= SITE_CRAWL_MAX_API_CALLS or fetcher.expired():
                break
            variants, paginated = _site_api_variants(kind, protos)
            working, empty200 = None, 0
            for vi, var in enumerate(variants):
                if stats["api"] >= SITE_CRAWL_MAX_API_CALLS or fetcher.expired():
                    break
                st, text = call_api(ep, var(1))
                if st is None or st in (401, 403, 404, 405, 410, 429):
                    return got_here         # dead / protected / limited: leave this endpoint
                if add(_site_extract(text)):
                    working = var
                    got_here = True
                    break
                if probe and vi == 0 and st != 200:
                    return got_here
                if st == 200:
                    empty200 += 1
                    if empty200 >= 2:       # answers fine but carries no links: not a proxy feed
                        break
            if working is None or not paginated:
                continue
            for page in range(2, 9):
                if (len(uris) >= want_raw or stats["api"] >= SITE_CRAWL_MAX_API_CALLS
                        or fetcher.expired()):
                    break
                st, text = call_api(ep, working(page))
                if st != 200 or not add(_site_extract(text)):
                    break
        return got_here

    # ---- seeds: the page the user typed, the site root, the sitemap ----
    seeds = [site_url]
    if site_url.rstrip("/") != origin:
        seeds.append(origin + "/")
    for s in seeds:
        push_page(s, 100, 0)
    push_page(origin + "/sitemap.xml", 50, 1)

    js_done = 0
    while not fetcher.expired() and len(uris) < want_raw:
        if ep_q and stats["api"] < SITE_CRAWL_MAX_API_CALLS and stats["endpoints"] < 8:
            ep = next((e for e in ep_q if not _site_is_feed(e)), ep_q[0])
            ep_q.remove(ep)
            stats["endpoints"] += 1
            if pull_endpoint(ep):
                stats["hits"] += 1
            continue
        if js_q and js_done < SITE_CRAWL_MAX_JS:
            u = js_q.pop(0)
            if u in js_seen:
                continue
            js_seen.add(u)
            js_done += 1
            st, text, _ct = fetcher.get(u)
            note_progress()
            if st == 200 and text:
                handle(u, text, 0, is_js=True)
            continue
        if heap and stats["pages"] < SITE_CRAWL_MAX_PAGES:
            _neg, _o, depth, u = heapq.heappop(heap)
            st, text, _ct = fetcher.get(u)
            stats["pages"] += 1
            note_progress()
            if st == 200 and text:
                handle(u, text, depth)
            continue
        break

    # Nothing found by reading the site itself: try the usual API locations once.
    if len(uris) < SITE_SHARE_MIN and not stats["hits"]:
        for path in SITE_WELL_KNOWN_API_PATHS:
            if fetcher.expired() or len(uris) >= want_raw or stats["api"] >= SITE_CRAWL_MAX_API_CALLS:
                break
            ep = origin + path
            if ep in ep_seen:
                continue
            ep_seen.add(ep)
            if pull_endpoint(ep, probe=True):
                stats["hits"] += 1

    stats["route"] = "VPN" if fetcher.route else ("direct" if fetcher.route is False else None)
    uris.sort(key=_site_group)              # stable: the site's own ranking is kept inside a group
    return uris[:want_raw], stats


def _site_safe_host(host: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", host.split(":")[0])


def _site_file_path(host: str, n: int = 1) -> str:
    """data/site_<host>.txt for the 1st search, then site_<host>2.txt, site_<host>3.txt ..."""
    return os.path.join(SITE_FILES_DIR, f"site_{_site_safe_host(host)}{n if n > 1 else ''}.txt")


def _site_existing_files(host: str) -> list:
    """[(number, path)] of the saved lists of this site, lowest number first."""
    pat = re.compile(rf"^site_{re.escape(_site_safe_host(host))}(\d*)\.txt$")
    out = []
    try:
        for name in os.listdir(SITE_FILES_DIR):
            m = pat.match(name)
            if m:
                out.append((int(m.group(1) or 1), os.path.join(SITE_FILES_DIR, name)))
    except OSError:
        pass
    return sorted(out)


def _site_files_cleanup(force: bool = False) -> int:
    """Delete data/site_*.txt lists older than SITE_FILE_MAX_AGE_DAYS (only our own files).
    Rate limited to once per SITE_FILE_CLEANUP_EVERY unless forced."""
    now = time.time()
    if not force and now - _state.get("site_cleanup_at", 0.0) < SITE_FILE_CLEANUP_EVERY:
        return 0
    _state["site_cleanup_at"] = now
    removed = 0
    try:
        for name in os.listdir(SITE_FILES_DIR):
            if not re.match(r"^(?:site_.+|channel_.+|source_T\d+(?:_\d+)?)\.txt$", name):
                continue
            path = os.path.join(SITE_FILES_DIR, name)
            try:
                if now - os.path.getmtime(path) > SITE_FILE_MAX_AGE_DAYS * 86400:
                    os.remove(path)
                    removed += 1
            except OSError:
                continue
    except OSError:
        pass
    return removed


def _site_save_file(host: str, site_url: str, uris: list):
    """One link per line (plus two comment lines): usable as a subscription file too.
    Every search of the same site writes a NEW file (site_<host>.txt, ...2.txt, ...3.txt)."""
    try:
        os.makedirs(SITE_FILES_DIR, exist_ok=True)
        _site_files_cleanup()
        existing = _site_existing_files(host)
        n = (existing[-1][0] + 1) if existing else 1
        path = _site_file_path(host, n)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(f"# Ramin VPN - protocols found on {site_url}\n")
            f.write(f"# saved {time.strftime('%Y-%m-%d %H:%M:%S')} - {len(uris)} links\n")
            f.write("\n".join(uris) + "\n")
        os.replace(tmp, path)
        return path
    except Exception:
        return None


def _channel_safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name or "")


def _channel_file_path(name: str, n: int = 1) -> str:
    """data/channel_<name>.txt for the 1st search of this channel, then
    channel_<name>2.txt, channel_<name>3.txt ... (a new file every time it is searched again)."""
    return os.path.join(SITE_FILES_DIR, f"channel_{_channel_safe_name(name)}{n if n > 1 else ''}.txt")


def _channel_existing_files(name: str) -> list:
    pat = re.compile(rf"^channel_{re.escape(_channel_safe_name(name))}(\d*)\.txt$")
    out = []
    try:
        for fname in os.listdir(SITE_FILES_DIR):
            m = pat.match(fname)
            if m:
                out.append((int(m.group(1) or 1), os.path.join(SITE_FILES_DIR, fname)))
    except OSError:
        pass
    return sorted(out)


def _tsrc_safe_name(source_index: int) -> str:
    return f"T{source_index + 1}"


def _tsrc_file_path(source_index: int, n: int = 1) -> str:
    """data/source_T<n>.txt for the 1st search of this source, then
    source_T<n>_2.txt, source_T<n>_3.txt ... (a new file every time it is searched again)."""
    tag = _tsrc_safe_name(source_index)
    return os.path.join(SITE_FILES_DIR, f"source_{tag}{f'_{n}' if n > 1 else ''}.txt")


def _tsrc_existing_files(source_index: int) -> list:
    tag = _tsrc_safe_name(source_index)
    pat = re.compile(rf"^source_{re.escape(tag)}(?:_(\d+))?\.txt$")
    out = []
    try:
        for fname in os.listdir(SITE_FILES_DIR):
            m = pat.match(fname)
            if m:
                out.append((int(m.group(1) or 1), os.path.join(SITE_FILES_DIR, fname)))
    except OSError:
        pass
    return sorted(out)


def _tsrc_save_file(source_index: int, source_name: str, raw_lines: list):
    """One config per line, saved BEFORE health-testing starts (mirrors _site_save_file /
    _channel_save_file) - only for the explicit T<n> command (see discover_free_vless's
    `verbose` flag), not for the automatic FV chain or Switch Sub."""
    if not raw_lines:
        return None
    try:
        os.makedirs(SITE_FILES_DIR, exist_ok=True)
        _site_files_cleanup()
        existing = _tsrc_existing_files(source_index)
        n = (existing[-1][0] + 1) if existing else 1
        path = _tsrc_file_path(source_index, n)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(f"# Ramin VPN - configs downloaded from source {_tsrc_safe_name(source_index)} "
                    f"({source_name})\n")
            f.write(f"# saved {time.strftime('%Y-%m-%d %H:%M:%S')} - {len(raw_lines)} links\n")
            f.write("\n".join(raw_lines) + "\n")
        os.replace(tmp, path)
        return path
    except Exception:
        return None


def _channel_save_file(name: str, raw_lines: list):
    """One config per line, saved BEFORE health-testing starts (mirrors _site_save_file)."""
    if not raw_lines:
        return None
    try:
        os.makedirs(SITE_FILES_DIR, exist_ok=True)
        _site_files_cleanup()
        existing = _channel_existing_files(name)
        n = (existing[-1][0] + 1) if existing else 1
        path = _channel_file_path(name, n)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(f"# Ramin VPN - protocols found in Telegram @{name}\n")
            f.write(f"# saved {time.strftime('%Y-%m-%d %H:%M:%S')} - {len(raw_lines)} links\n")
            f.write("\n".join(raw_lines) + "\n")
        os.replace(tmp, path)
        return path
    except Exception:
        return None


def _channel_plan_from_saved(name: str, uris: list, limit: int) -> list:
    """Same shape/tagging as _tg_channel_plan, built from a saved channel_<name>.txt
    list instead of a fresh read (used when the channel cannot be reached right now)."""
    plan, fps = [], set()
    for uri in uris:
        try:
            ob = parse_proxy_uri(uri, 0, extended=True)
        except Exception:
            ob = None
        if not ob:
            continue
        fp = _ob_fingerprint(ob)
        if fp in fps:
            continue
        fps.add(fp)
        ob["tag"] = f"PX-TG_@{name}-{ob.get('tag', '').lstrip()}".strip()
        plan.append(ob)
        if len(plan) >= limit:
            break
    return plan


def _channel_load_saved(name: str) -> list:
    """The newest saved list of this channel (used when the channel cannot be read right now)."""
    files = _channel_existing_files(name)
    if not files:
        return []
    try:
        newest = max(files, key=lambda item: os.path.getmtime(item[1]))[1]
        with open(newest, "r", encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except Exception:
        return []


def _site_load_saved(host: str) -> list:
    """The newest saved list of this site (used when the site cannot be read right now)."""
    files = _site_existing_files(host)
    if not files:
        return []
    try:
        newest = max(files, key=lambda item: os.path.getmtime(item[1]))[1]
        with open(newest, "r", encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except Exception:
        return []


def _site_plan_from_uris(uris: list, host: str, limit: int) -> list:
    """Parse the saved links into candidate outbounds (same shape as every other source)."""
    plan, fps = [], set()
    for i, uri in enumerate(uris, 1):
        try:
            ob = parse_proxy_uri(uri, i, extended=True)
        except Exception:
            ob = None
        if not ob:
            continue
        fp = _ob_fingerprint(ob)
        if fp in fps:
            continue
        fps.add(fp)
        ob["tag"] = f"PX-Site_{host}-{str(ob.get('tag', '')).lstrip()}".strip()
        plan.append(ob)
        if len(plan) >= limit:
            break
    return plan


@_requires_isp_org
def connect_by_site(binary: str, site_url: str, wanted: str = None, proto_name: str = None,
                    want_udp: bool = False, want_count: int = None):
    """SW 'freeproxydb.com' (optionally + a protocol, 'udp', and/or a count): crawl that
    website (through the tunnel first), save the protocols it publishes to
    data/site_<host>.txt (a new numbered file per search), test them on the NORMAL internet
    (no VPN) and connect to the first healthy one; the rest are tested silently in the
    background so 'Switch Server : 1 - N' fills up with servers of this site.
    Returns (status, data) exactly like connect_by_telegram_channel_filtered."""
    if not SITE_SEARCH_ENABLED:
        return "none", None
    host = urllib.parse.urlsplit(site_url).netloc.lower()
    prev = (_state.get("free_vless_mode"), _state.get("free_source_index"),
            _state.get("free_verified_pool"))
    bootstrapped = False

    def crawl():
        wait = FreeWaitDisplay(1, SITE_CRAWL_MAX_PAGES).start()
        try:
            return crawl_site_for_proxies(site_url, progress=lambda: wait.tick(1))
        finally:
            wait.stop(0)

    def give_up():
        if bootstrapped:                       # do not leave the helper tunnel behind
            kill_singbox()
            _state["cleaned_up"] = False
        _state["free_vless_mode"], _state["free_source_index"], _state["free_verified_pool"] = prev

    print(f"{INFO} Website search: {host} ...")
    # 1) crawl - through the tunnel FIRST when one is up, direct fallback
    uris, info = crawl()
    if not uris and not _local_tunnel_up(refresh=0):
        # No tunnel yet and the site may be filtered: get ANY healthy server first
        # (same bootstrap as SW '@channel'), then read the site through it.
        print(f"{INFO} No tunnel yet - bootstrapping a server to reach {host} ...")
        b_status, _b = connect_by_web_text(binary, "vless free config")
        if b_status == "ok" and _local_tunnel_up(refresh=0):
            bootstrapped = True
            uris, info = crawl()
    if not uris:
        old = _site_load_saved(host)
        if old:
            print(f"{WARN} {host} could not be read - using the list saved earlier ({len(old)})")
            uris = old
    if not uris:
        print(f"{FAIL} No proxy protocols found on {host}")
        give_up()
        return "none", None

    # 2) save the list to a file
    plan = _site_plan_from_uris(uris, host, SITE_TARGET_CANDIDATES)
    if wanted:
        plan = [ob for ob in plan if _protocol_match(ob, wanted)]
    elif want_udp:
        plan = [ob for ob in plan if str(ob.get("type")) in UDP_CAPABLE_PROTOCOLS]
    if not plan:
        what = f"any {proto_name or wanted}" if wanted else ("any UDP-capable protocol" if want_udp else "links")
        print(f"{FAIL} {host}: found links, but none matched {what}")
        give_up()
        return "none", None
    path = _site_save_file(host, site_url, uris)
    kinds = {}
    for ob in plan:
        kinds[str(ob.get("type"))] = kinds.get(str(ob.get("type")), 0) + 1
    mix = ", ".join(f"{k} {v}" for k, v in sorted(kinds.items(), key=lambda kv: -kv[1])[:5])
    where = f" -> {os.path.relpath(path)}" if path else ""
    print(f"{OK} {host}: {len(plan)} protocols ({mix}){where}")

    # 3) test on the NORMAL internet, connect to the first healthy one
    print(f"{INFO} Testing on your normal internet (no VPN) ...")
    good, bad = [], set()
    wait = FreeWaitDisplay(1, 50).start()
    try:
        wait.set_progress_total(len(plan))
        good, bad = _quiet_verify(
            binary, plan, level=0, stop_after=(want_count or 1), workers=SITE_VERIFY_WORKERS,
            deadline=time.monotonic() + SITE_VERIFY_BUDGET, country=None,
            on_done=lambda ok: wait.tick(1), want_udp=want_udp)
    finally:
        wait.stop(1 if good else 0)
    if not good:
        print(f"{FAIL} {host}: none of the {len(plan)} protocols is healthy right now")
        give_up()
        return "failed", None

    # 4) connect - mirrors connect_by_telegram_channel_filtered
    pool = [ob for ob, _ in good]
    kill_singbox()
    _state["cleaned_up"] = False
    _state["free_vless_mode"] = True
    _state["free_source_index"] = -1  # sentinel: NOT a real T<n> source (same as web/@channel searches)
    _state["free_verified_pool"] = pool[:FREE_VLESS_COUNT]
    proc, tag, ok = connect_with_fallback(binary, pool, pool[0]["tag"], False, pool,
                                          label=f"Site 🌐 {host}", enable_fragment=None)
    if tag and ok:
        save_switch_server_pool(switch_server_cache_key(True, -1), pool)
        _dual_health_report(pool, f"Site {host}")
        if _RESERVE is not None:
            # The rest of the list is tested silently in the background; healthy ones
            # become Switch Server 2..N (all of them, up to SITE_SWITCH_MAX; ONLY servers of this site).
            by_tag = {ob["tag"]: ob for ob in plan}
            bad_fps = {_ob_fingerprint(by_tag[t]) for t in bad if t in by_tag}
            pool_fps = {_ob_fingerprint(ob) for ob in pool}
            rest = [ob for ob in plan
                    if _ob_fingerprint(ob) not in pool_fps and _ob_fingerprint(ob) not in bad_fps]
            _RESERVE.set_site_feed(rest, host, bad_fps=bad_fps, enough=want_count, hard_cap=want_count)
            _RESERVE.udp_only = want_udp
        return "ok", (proc, tag, True, pool, pool[0]["tag"], -1)
    kill_singbox()
    _state["cleaned_up"] = False
    _state["free_vless_mode"], _state["free_source_index"], _state["free_verified_pool"] = prev
    return "failed", None


# ============================================================================
# Search Web + country / protocol / ping: freeproxydb.com FIRST
# ============================================================================
# Round 1: 300 links of freeproxydb.com are tested (on the normal internet). If none is
# healthy, round 2 tests the next 300, then round 3 the next 300. Only after those three
# rounds the search continues in every other source ("the whole web", the normal search).
SW_SITE_FIRST_ENABLED = True
SW_SITE_FIRST_URL = "https://freeproxydb.com"
SW_SITE_ROUND_SIZE = 300
SW_SITE_ROUNDS = 3
SW_SITE_ROUND_BUDGET = 200.0     # seconds one round of 300 may take
SW_SITE_FIRST_ENOUGH = 6         # country / protocol / ping from freeproxydb: 6 healthy servers are enough - stop testing
SW_SITE_FIRST_MAX = 10           # ...and never keep more than this many (servers that pass in the same batch)
_SW_SITE_PAGE_SIZE = 100
_SW_SITE_LINK_TYPES = {"vless": "vless", "vmess": "vmess", "trojan": "trojan", "shadowsocks": "ss"}
_SW_SITE_SHARE_LINK_TYPES = "vless,vmess,trojan,ss"    # country / ping searches: share links only


def _sw_site_params(kind: str, wanted, country, page: int, level: int):
    """Query parameters for freeproxydb's /api/proxy/search. level 0 = full, 2 = minimal (a
    strict server that answers 400 gets the next, plainer set). None = the site has no such protocol."""
    params = {"page_size": _SW_SITE_PAGE_SIZE, "page_index": page}
    if level == 0:
        params.update({"order_by": "check_success_count", "order_dir": "desc", "fields": "connect_string"})
    if country:
        params["country"] = country
    if kind == "protocol":
        if wanted in _SW_SITE_LINK_TYPES:
            params["link_type"] = _SW_SITE_LINK_TYPES[wanted]
        elif wanted in FREEPROXYDB_PROTOCOL_MAP:
            params["protocol"] = FREEPROXYDB_PROTOCOL_MAP[wanted]
        else:
            return None
    else:
        params["link_type"] = _SW_SITE_SHARE_LINK_TYPES
    return params


def _sw_site_fetch_pages(fetcher, origin: str, kind: str, wanted, country, page_from: int, page_to: int,
                         state: dict) -> list:
    """Links of result pages page_from..page_to (100 per page). state remembers which
    parameter set worked so later rounds do not probe again."""
    out = []
    for page in range(page_from, page_to + 1):
        if fetcher.expired():
            break
        got = []
        for level in ([state["level"]] if state.get("level") is not None else [0, 2]):
            params = _sw_site_params(kind, wanted, country, page, level)
            if params is None:
                return out
            url = f"{origin}/api/proxy/search?{urllib.parse.urlencode(params, safe=',')}"
            st, text, _ct = fetcher.get(url)
            if st == 429:
                try:
                    wait = min(float(fetcher.retry_after or 8), 15.0)
                except Exception:
                    wait = 8.0
                time.sleep(wait)
                st, text, _ct = fetcher.get(url)
            if st == 200:
                got = _site_extract(text)
                if got:
                    state["level"] = level
                    break
            elif st in (400, 422):
                continue           # unknown parameter: try the plainer set
            else:
                break
        if not got:
            break                  # no more pages
        out.extend(got)
    return out


def _sw_site_crawl_fallback(kind: str, wanted, country, want: int) -> list:
    """The API gave nothing: read the site the normal way and filter what it published."""
    try:
        uris, _info = crawl_site_for_proxies(SW_SITE_FIRST_URL, target=want)
    except Exception:
        return []
    if kind == "protocol" and wanted:
        uris = [u for u in uris if _protocol_match_uri(u, wanted)]
    if country:
        matched = [u for u in uris if _remark_matches_country(_line_remark(u), country)]
        uris = matched + [u for u in uris if u not in set(matched)]
    return uris


def _protocol_match_uri(uri: str, wanted: str) -> bool:
    try:
        ob = parse_proxy_uri(uri, 1, extended=True)
    except Exception:
        ob = None
    return bool(ob) and _protocol_match(ob, wanted)


def _sw_site_ping_round(binary: str, plan: list, upper_ms: int, target: int, wait, deadline: float,
                        keep: int = None) -> list:
    """Real-request latency of every candidate; keeps the ones within 1..upper_ms ms."""
    results, lock, stop_evt = [], threading.Lock(), threading.Event()

    def worker(ob):
        if stop_evt.is_set() or time.monotonic() >= deadline:
            wait.tick(1)
            return
        ok, delay_ms, _err = _verify_one_fv_sublink(
            binary, ob, ["https://www.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204",
                         "https://www.google.com/generate_204"], quality=0)
        wait.tick(1)
        if ok and delay_ms is not None and 0 < float(delay_ms) <= upper_ms:
            with lock:
                results.append((ob, float(delay_ms) / 1000.0))
                if len(results) >= target:
                    stop_evt.set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(FV_PING_WORKERS, len(plan)))) as ex:
        for fut in concurrent.futures.as_completed([ex.submit(worker, ob) for ob in plan]):
            try:
                fut.result()
            except Exception:
                pass
    results.sort(key=lambda x: x[1])
    return results[:max(target, keep or 0)]


@_requires_isp_org
def connect_by_site_first(binary: str, kind: str, wanted: str = None, proto_name: str = None,
                          country: str = None, country_name: str = None, ping_ms: int = None,
                          want_udp: bool = False, want_count: int = None):
    """Search Web + protocol / country / ping: look on freeproxydb.com FIRST (3 rounds of
    SW_SITE_ROUND_SIZE links). Returns ("ok", data) with the same data as connect_by_protocol /
    connect_by_country / connect_by_ping; ("none", None) when the site had nothing healthy - the
    caller then runs the normal (whole web) search."""
    if not (SW_SITE_FIRST_ENABLED and SITE_SEARCH_ENABLED):
        return "none", None
    parts = urllib.parse.urlsplit(SW_SITE_FIRST_URL)
    host, origin = parts.netloc.lower(), f"{parts.scheme}://{parts.netloc}"
    upper_ms = ping_search_upper_bound(ping_ms) if kind == "ping" else None
    what = {"protocol": f"{proto_name or wanted}" + (f" in {country_name}" if country_name else ""),
            "country": f"{country_name or country}", "ping": f"ping 1-{upper_ms} ms"}.get(kind, kind)
    print(f"{INFO} {host} first: {what} ...")

    prev = (_state.get("free_vless_mode"), _state.get("free_source_index"),
            _state.get("free_verified_pool"))
    fetcher = _SiteFetcher(time.monotonic() + SITE_CRAWL_TIME_BUDGET * SW_SITE_ROUNDS)
    api_state, seen = {}, set()
    pages_per_round = max(1, SW_SITE_ROUND_SIZE // _SW_SITE_PAGE_SIZE)
    fallback_uris = None
    level = 0
    if kind == "country":
        level = min(_fv_quality_level_now(), FV_COUNTRY_QUALITY_LEVEL) if FV_QUALITY_MODE else 0

    good, bad, plan = [], set(), []
    save_path, downloaded_all = None, []   # data/site_<host>.txt - written BEFORE each round is tested
    for rnd in range(SW_SITE_ROUNDS):
        first_page = rnd * pages_per_round + 1
        uris = _sw_site_fetch_pages(fetcher, origin, kind, wanted, country,
                                    first_page, first_page + pages_per_round - 1, api_state)
        if not uris and rnd == 0:
            if kind == "protocol" and wanted not in _SW_SITE_LINK_TYPES and wanted not in FREEPROXYDB_PROTOCOL_MAP:
                return "none", None          # the site does not carry this protocol
            fallback_uris = _sw_site_crawl_fallback(kind, wanted, country,
                                                    SW_SITE_ROUND_SIZE * SW_SITE_ROUNDS)
        if fallback_uris is not None:
            uris = fallback_uris[rnd * SW_SITE_ROUND_SIZE:(rnd + 1) * SW_SITE_ROUND_SIZE]
        if not uris:
            break                            # the site has no more links: stop the rounds

        # SAVE what was just downloaded - BEFORE any health testing of this round -
        # to data/site_<host>.txt (one growing file per search; a new numbered file
        # only starts the NEXT time this same site is searched again).
        downloaded_all.extend(uris)
        if save_path is None:
            existing = _site_existing_files(host)
            n = (existing[-1][0] + 1) if existing else 1
            save_path = _site_file_path(host, n)
        try:
            os.makedirs(SITE_FILES_DIR, exist_ok=True)
            tmp = save_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(f"# Ramin VPN - protocols found on {SW_SITE_FIRST_URL} (Search Web + {kind})\n")
                f.write(f"# saved {time.strftime('%Y-%m-%d %H:%M:%S')} - {len(downloaded_all)} links\n")
                f.write("\n".join(downloaded_all) + "\n")
            os.replace(tmp, save_path)
            print(f"{OK} round {rnd + 1}: {len(uris)} configs downloaded and saved "
                  f"-> {os.path.relpath(save_path)} ({len(downloaded_all)} total)")
        except Exception:
            pass

        plan = []
        for ob in _site_plan_from_uris(uris, host, SW_SITE_ROUND_SIZE * 2):
            fp = _ob_fingerprint(ob)
            if fp in seen or (kind == "protocol" and wanted and not _protocol_match(ob, wanted)):
                continue
            if want_udp and not wanted and str(ob.get("type")) not in UDP_CAPABLE_PROTOCOLS:
                continue
            seen.add(fp)
            plan.append(ob)
            if len(plan) >= SW_SITE_ROUND_SIZE:
                break
        if not plan:
            continue
        print(f"{INFO} {host}: round {rnd + 1}/{SW_SITE_ROUNDS} - testing {len(plan)} links "
              f"on your normal internet ...")
        wait = FreeWaitDisplay(1, 50).start()
        deadline = time.monotonic() + SW_SITE_ROUND_BUDGET
        try:
            wait.set_progress_total(len(plan))
            if kind == "ping":
                matches = _sw_site_ping_round(binary, plan, upper_ms, want_count or SW_SITE_FIRST_ENOUGH,
                                              wait, deadline, keep=want_count or SW_SITE_FIRST_MAX)
                good, bad = list(matches), set()
            else:
                good, bad = _quiet_verify(
                    binary, plan, level=level, stop_after=(want_count or 1),
                    workers=(FV_COUNTRY_WORKERS if kind == "country" else FV_PROTOCOL_WORKERS),
                    deadline=deadline, country=country, on_done=lambda ok: wait.tick(1),
                    want_udp=want_udp)
        finally:
            wait.stop(1 if good else 0)
        if good:
            break
    if not good:
        print(f"{WARN} {host}: nothing healthy in {SW_SITE_ROUNDS} rounds - searching the rest of the web ...")
        return "none", None

    pool = [ob for ob, _ in good]
    kill_singbox()
    _state["cleaned_up"] = False
    _state["free_vless_mode"] = True
    _state["free_source_index"] = -1
    _state["free_verified_pool"] = pool[:FREE_VLESS_COUNT]
    proc, tag, ok = connect_with_fallback(binary, pool, pool[0]["tag"], False, pool,
                                          label=f"Site 🌐 {host}", enable_fragment=None)
    if not (tag and ok):
        kill_singbox()
        _state["cleaned_up"] = False
        _state["free_vless_mode"], _state["free_source_index"], _state["free_verified_pool"] = prev
        return "failed", None
    save_switch_server_pool(switch_server_cache_key(True, -1), pool)
    if _RESERVE is not None:
        if kind == "ping":
            _RESERVE.set_country(None)     # same as a normal ping search: the pool IS the match list
            _RESERVE.clear()
        else:
            by_tag = {ob["tag"]: ob for ob in plan}
            bad_fps = {_ob_fingerprint(by_tag[t]) for t in bad if t in by_tag}
            pool_fps = {_ob_fingerprint(ob) for ob in pool}
            rest = [ob for ob in plan if _ob_fingerprint(ob) not in pool_fps
                    and _ob_fingerprint(ob) not in bad_fps]
            _RESERVE.set_site_feed(rest, host, bad_fps=bad_fps,
                                   country=country, country_name=country_name,
                                   enough=(want_count or SW_SITE_FIRST_ENOUGH),
                                   hard_cap=(want_count or SW_SITE_FIRST_MAX))
            _RESERVE.udp_only = want_udp
    return "ok", (proc, tag, True, pool, pool[0]["tag"], -1)


def discover_telegram_sources(wanted: str, max_count: int, extra_terms: list = None) -> list:
    """Telegram's global search (contacts.search) to find PUBLIC CHANNELS not already
    in T25/T26's TGParse list, by keyword - the one part of discovery that genuinely
    needs a logged-in account, because finding UNKNOWN channels isn't possible through
    an anonymous request. Once a channel is found, its posts are read exactly the way
    T25/T26 already read known channels (fetch_telegram_channel_configs, no login) -
    only the "find the channel in the first place" step is new. Silent/optional: no
    api_id+api_hash+session (see telegram_login.py) simply means [] here, nothing else
    in the program is affected."""
    if not TELEGRAM_DISCOVERY_ENABLED:
        return []
    canonical = _PROTOCOL_CANONICAL.get(wanted, wanted)
    terms = [canonical] + (extra_terms or []) + ["free config"]
    cache_key = f"{wanted}:{'|'.join(extra_terms or [])}"
    now = time.monotonic()
    hit = _TELEGRAM_DISCOVERY_CACHE.get(cache_key)
    if hit and now - hit[0] < TELEGRAM_DISCOVERY_CACHE_TTL:
        return hit[1]

    ns = f"tg:{wanted}"
    lines = []
    client = _telegram_client()
    if client is None:
        return []
    try:
        from telethon.tl.functions.contacts import SearchRequest
        usernames, seen = [], set()
        for term in terms:
            try:
                res = client(SearchRequest(q=term, limit=TELEGRAM_DISCOVERY_MAX_CHANNELS))
            except Exception:
                continue
            for chat in getattr(res, "chats", []) or []:
                uname = getattr(chat, "username", None)
                is_broadcast = getattr(chat, "broadcast", False)  # channel, not a group/user
                if uname and is_broadcast and uname not in seen:
                    seen.add(uname)
                    usernames.append(uname)
            if len(usernames) >= TELEGRAM_DISCOVERY_MAX_CHANNELS:
                break

        remembered = [k for k, s in _DISCOVERY_MEMORY.summary(ns) if s > 0.35]
        for uname in remembered:
            if uname not in seen:
                seen.add(uname)
                usernames.insert(0, uname)  # known-good channels checked first

        for uname in usernames[:TELEGRAM_DISCOVERY_MAX_CHANNELS + len(remembered)]:
            try:
                text = fetch_telegram_channel_configs(f"https://t.me/s/{uname}")
            except Exception:
                text = ""
            got = _proxy_lines_from_text(text)
            if got:
                lines.extend(got)
            _DISCOVERY_MEMORY.record(ns, uname, bool(got))
    except Exception:
        pass
    finally:
        try:
            client.disconnect()
        except Exception:
            pass

    plan = _protocol_plan_from_lines(lines, wanted, max_count, tag_prefix="PX-Telegram_Discovery-")
    _TELEGRAM_DISCOVERY_CACHE[cache_key] = (now, plan)
    return plan


def _discovery_status_note() -> str:
    """One short line shown above the Search Web prompt so it's obvious, without
    guessing, whether GHDISC/TGDISC are actually active for this search."""
    web = "Web: ON" if WEB_DISCOVERY_ENABLED else "Web: OFF"
    gh = "GitHub: ON" if GITHUB_DISCOVERY_ENABLED else "GitHub: OFF"
    tg = "Telegram: ON" if TELEGRAM_DISCOVERY_ENABLED else "Telegram: OFF"
    return f"{web}   {gh}   {tg}"


def _protocol_plan_from_lines(lines: list, wanted: str, max_count: int,
                              tag_prefix: str, skip=None) -> list:
    """Parse up to max_count candidates matching one requested protocol."""
    if not lines:
        return []
    skip = skip or set()
    order = list(range(len(lines)))
    random.shuffle(order)
    out, seen = [], set(skip)
    for pos in order:
        line = lines[pos]
        low = line.lower()
        if wanted == "vless" and not low.startswith("vless://"): continue
        if wanted == "vmess" and not low.startswith("vmess://"): continue
        if wanted == "trojan" and not low.startswith("trojan://"): continue
        if wanted == "hysteria2" and not (low.startswith("hysteria2://") or low.startswith("hy2://")): continue
        if wanted == "hysteria" and not (low.startswith("hysteria://") or low.startswith("hy://")): continue
        if wanted == "wireguard" and not (low.startswith("wireguard://") or low.startswith("warp://")): continue
        if wanted == "shadowsocks" and not low.startswith("ss://"): continue
        if wanted == "tuic" and not low.startswith("tuic://"): continue
        if wanted == "shadowtls" and not low.startswith("shadowtls://"): continue
        if wanted == "anytls" and not low.startswith("anytls://"): continue
        if wanted == "naive" and not (low.startswith("naive://") or low.startswith("naive+https://") or low.startswith("naive+quic://")): continue
        if wanted == "ssh" and not low.startswith("ssh://"): continue
        if wanted == "snell" and not low.startswith("snell://"): continue
        if wanted == "socks" and not low.startswith(("socks://", "socks4://", "socks4a://", "socks5://")): continue
        if wanted == "http" and not low.startswith(("http://", "https://")): continue
        try:
            ob = parse_proxy_uri(line, pos + 1, extended=True)
        except Exception:
            ob = None
        if not ob or not _protocol_match(ob, wanted):
            continue
        fp = _ob_fingerprint(ob)
        if fp in seen:
            continue
        seen.add(fp)
        ob["tag"] = f"{tag_prefix}{ob.get('tag', '').lstrip()}".strip()
        out.append(ob)
        if len(out) >= max_count:
            break
    return out


def _country_plan_for_source(src_index: int, code: str, tier1_max: int, blind_max: int, skip=None) -> list:
    """Candidates of one source for a country search: configs whose NAME mentions
    the country first, then a few random others (a name says little about the real exit)."""
    lines = _fv_source_lines(src_index)
    if not lines:
        return []
    src_code = get_free_vless_source_code(src_index)
    order = list(range(1, len(lines) + 1))
    random.shuffle(order)
    tier1, rest = [], []
    for i in order:
        if len(tier1) >= tier1_max and len(rest) >= blind_max:
            break
        line = lines[i - 1]
        matched = _remark_matches_country(_line_remark(line), code)
        bucket, limit = (tier1, tier1_max) if matched else (rest, blind_max)
        if len(bucket) >= limit:
            continue
        try:
            ob = parse_proxy_uri(line, i, extended=True)
        except Exception:
            ob = None
        if not ob or (skip and _ob_fingerprint(ob) in skip):
            continue
        ob["tag"] = f"FV-{src_code}-{ob['tag']}"
        bucket.append(ob)
    return tier1 + rest


def _protocol_plan_for_source(src_index: int, wanted: str, max_count: int, skip=None, country=None) -> list:
    """Build a bounded list of parsed configs matching the requested protocol."""
    lines = _fv_source_lines(src_index)
    if not lines:
        return []
    code = get_free_vless_source_code(src_index)
    order = list(range(1, len(lines) + 1))
    random.shuffle(order)
    out = []
    skip = skip or set()
    for i in order:
        line = lines[i - 1]
        # Cheap scheme pre-filter before parsing. This keeps giant feeds fast.
        low = line.lower()
        if wanted == "vless" and not low.startswith("vless://"): continue
        if wanted == "vmess" and not low.startswith("vmess://"): continue
        if wanted == "trojan" and not low.startswith("trojan://"): continue
        if wanted == "hysteria2" and not (low.startswith("hysteria2://") or low.startswith("hy2://")): continue
        if wanted == "hysteria" and not low.startswith("hysteria://"): continue
        if wanted == "wireguard" and not (low.startswith("wireguard://") or low.startswith("warp://")): continue
        if wanted == "shadowsocks" and not low.startswith("ss://"): continue
        if wanted == "tuic" and not low.startswith("tuic://"): continue
        if wanted == "shadowtls" and not low.startswith("shadowtls://"): continue
        if wanted == "anytls" and not low.startswith("anytls://"): continue
        if wanted == "naive" and not (low.startswith("naive://") or low.startswith("naive+https://") or low.startswith("naive+quic://")): continue
        if wanted == "ssh" and not low.startswith("ssh://"): continue
        if wanted == "snell" and not low.startswith("snell://"): continue
        if wanted == "socks" and not low.startswith(("socks://", "socks4://", "socks4a://", "socks5://")): continue
        if wanted == "http" and not low.startswith(("http://", "https://")): continue
        try:
            ob = parse_proxy_uri(line, i, extended=True)
        except Exception:
            ob = None
        if not ob or not _protocol_match(ob, wanted):
            continue
        if _ob_fingerprint(ob) in skip:
            continue
        ob["tag"] = f"FV-{code}-{ob['tag']}"
        out.append(ob)
        if len(out) >= max_count:
            break
    return out

def _rank_sources(ns: str, keys: list) -> list:
    """Search order: T1 ALWAYS first, then every other source in the order the
    result memory recommends. Nothing is ever excluded - if T1 has nothing, the search simply goes on
    to the next source (and finally through all of them)."""
    ranked = _SOURCE_MEMORY.rank(ns, [k for k in keys if k != "T1"])
    return (["T1"] if "T1" in keys else []) + ranked


def _protocol_source_defs(binary: str, wanted: str, country=None) -> list:
    """Every place a protocol can be searched, in the DEFAULT order, as [(key, builder)].
    builder() downloads / generates that source and returns parsed candidates. Keys:
    EXTRA:<feed name>, WARP, FPDB and T<n>. The default order puts the dedicated protocol
    feeds first (that is where rare protocols live) and the general T1..Tn sources last;
    the result memory then reorders it."""
    per = FV_PROTOCOL_MAX_PER_SOURCE
    defs = []
    for url, label in PROTOCOL_EXTRA_SOURCE_URLS.get(wanted, []):
        defs.append((f"EXTRA:{label}",
                     lambda u=url, l=label: _protocol_plan_from_lines(
                         _protocol_extra_lines(u, cache_key=f"extra:{wanted}:{u}"), wanted, per,
                         tag_prefix=f"PX-{l.replace(' ', '_')}-")))
    if wanted == "wireguard":
        # shared WARP lists are thin and stale: register a few fresh identities right now
        defs.append(("WARP", lambda: _protocol_plan_from_lines(
            generate_fresh_warp_uris(binary, count=3), wanted, per,
            tag_prefix="PX-Cloudflare_WARP_Live-")))
    if wanted in FREEPROXYDB_PROTOCOL_MAP:
        defs.append(("FPDB", lambda: _protocol_plan_from_lines(
            _freeproxydb_protocol_lines(wanted), wanted, per, tag_prefix="PX-FreeProxyDB-")))
    for src in range(len(FREE_VLESS_SOURCES)):
        defs.append((f"T{src + 1}", lambda s=src: _protocol_plan_for_source(s, wanted, per, country=country)))
    # Live discovery last: only worth the extra network round-trips (GitHub search,
    # Telegram global search) once the fixed T1-Tn / EXTRA / FPDB feeds above come up
    # short or are all down - e.g. a repo got deleted/renamed. Same result memory, same
    # verification, same silent background pool-fill as every source above.
    if WEB_DISCOVERY_ENABLED:
        defs.append(("WEBDISC", lambda: discover_web_sources(wanted, per)))
    if GITHUB_DISCOVERY_ENABLED:
        defs.append(("GHDISC", lambda: discover_github_sources(wanted, per)))
    if TELEGRAM_DISCOVERY_ENABLED:
        defs.append(("TGDISC", lambda: discover_telegram_sources(wanted, per)))
    return defs


def search_protocol_server(binary: str, wanted: str, country: str = None, silent: bool = False,
                           want_udp: bool = False, want_count: int = None):
    """Find ONE healthy server of a protocol (optionally with a real exit country).

    Sources (T1..Tn, dedicated protocol feeds, FreeProxyDB, WARP) are tried one after the
    other in the order the RESULT MEMORY recommends: the sources that delivered a working
    server for this protocol before come first, sources that were always empty come last (never
    excluded - feeds change). Each source is downloaded only when its turn comes and gets
    FV_PROTOCOL_SOURCE_BUDGET seconds; candidates left untested get a second pass at the end.
    Every candidate is verified with a real sing-box end-to-end request before it is chosen.

    Returns (pool, manual_tag, source_index) or (None, None, None)."""
    deadline = time.monotonic() + FV_PROTOCOL_TIME_BUDGET
    wait = (_SilentWait() if silent else FreeWaitDisplay(1, 50)).start()
    ns = f"proto:{wanted}"
    defs = _protocol_source_defs(binary, wanted, country)
    builders = dict(defs)
    order = _rank_sources(ns, [k for k, _ in defs])
    learn_misses = not country   # a miss with a country filter says little about the feed itself
    seen, key_of_fp, leftovers = set(), {}, []
    stop_n = [0]

    def src_index(key):
        if key.startswith("T") and key[1:].isdigit():
            return int(key[1:]) - 1
        return len(FREE_VLESS_SOURCES) - 1   # extra feeds: keep FV failover in a valid state

    try:
        for key in order:
            if time.monotonic() >= deadline:
                break
            try:
                plan = builders[key]()
            except Exception:
                plan = []
            plan = [ob for ob in plan if _ob_fingerprint(ob) not in seen]
            for ob in plan:
                seen.add(_ob_fingerprint(ob))
                key_of_fp[_ob_fingerprint(ob)] = key
            if not plan:
                if learn_misses:
                    _SOURCE_MEMORY.record(ns, key, False)
                continue
            wait.set_progress_total(len(plan))
            t0 = time.monotonic()
            good, bad = _quiet_verify(
                binary, plan, level=0, stop_after=(want_count or 1), workers=FV_PROTOCOL_WORKERS,
                deadline=min(deadline, t0 + FV_PROTOCOL_SOURCE_BUDGET), country=country,
                on_done=lambda ok: wait.tick(1), want_udp=want_udp
            )
            if good:
                _SOURCE_MEMORY.record(ns, key, True, time.monotonic() - t0)
                found = [ob for ob, _ in good]
                stop_n[0] = len(found)
                return found, found[0]["tag"], src_index(key)
            if learn_misses:
                _SOURCE_MEMORY.record(ns, key, False)
            leftovers.extend(ob for ob in plan if ob.get("tag") not in bad)

        # second pass: candidates a source had no time for
        if leftovers and time.monotonic() < deadline:
            wait.set_progress_total(len(leftovers))
            t0 = time.monotonic()
            good, _bad = _quiet_verify(
                binary, leftovers, level=0, stop_after=(want_count or 1), workers=FV_PROTOCOL_WORKERS,
                deadline=deadline, country=country, on_done=lambda ok: wait.tick(1), want_udp=want_udp
            )
            if good:
                found = [ob for ob, _ in good]
                key = key_of_fp.get(_ob_fingerprint(found[0]), f"T{len(FREE_VLESS_SOURCES)}")
                _SOURCE_MEMORY.record(ns, key, True, time.monotonic() - t0)
                stop_n[0] = len(found)
                return found, found[0]["tag"], src_index(key)
        return None, None, None
    finally:
        wait.stop(stop_n[0])


@_requires_isp_org
def connect_by_protocol(binary: str, wanted: str, display_name: str, country: str = None,
                        silent: bool = False, label: str = None, want_udp: bool = False,
                        want_count: int = None):
    """Find and connect to a requested protocol without using S1-S8.

    Connects to the FIRST healthy server of that protocol. Afterwards the reserve
    (silent background search on the phone's normal internet) looks for more servers
    of the same protocol - and for other protocols only if too few exist - so that
    "Switch Server : 1 - N" fills up without the user noticing anything."""
    pool, manual, src = search_protocol_server(binary, wanted, country=country, silent=silent,
                                               want_udp=want_udp, want_count=want_count)
    if not pool:
        return "none", None
    kill_singbox()
    _state["cleaned_up"] = False
    # The screen is drawn inside connect_with_fallback(): set the FV state first.
    prev = (_state.get("free_vless_mode"), _state.get("free_source_index"),
            _state.get("free_verified_pool"))
    _state["free_vless_mode"] = True
    _state["free_source_index"] = src
    _state["free_verified_pool"] = pool[:FREE_VLESS_COUNT]
    proc, tag, ok = connect_with_fallback(binary, pool, manual, False, pool,
                                          label=label or f"Connected {display_name}", enable_fragment=None)
    if tag and ok:
        save_switch_server_pool(switch_server_cache_key(True, src), pool)
        if _RESERVE is not None:
            _RESERVE.set_binding(country=country,
                                 country_name=COUNTRY_NAMES.get(country, country) if country else None,
                                 protocol=wanted, protocol_name=display_name, fresh=True,
                                 count=want_count, udp_only=want_udp)
        return "ok", (proc, tag, True, pool, manual or tag, src)
    _state["free_vless_mode"], _state["free_source_index"], _state["free_verified_pool"] = prev
    kill_singbox()
    _state["cleaned_up"] = False
    return "failed", None

def _udp_any_plan_for_source(src_index: int, max_count: int, skip=None) -> list:
    """A bounded, de-duplicated slice of one FV source, kept to UDP-capable protocol
    types only - used by the bare SW 'udp' search (no protocol/country given)."""
    lines = _fv_source_lines(src_index)
    if not lines:
        return []
    src_code = get_free_vless_source_code(src_index)
    order = list(range(1, len(lines) + 1))
    random.shuffle(order)
    skip = skip or set()
    out = []
    for i in order:
        try:
            ob = parse_proxy_uri(lines[i - 1], i, extended=True)
        except Exception:
            ob = None
        if not ob or str(ob.get("type")) not in UDP_CAPABLE_PROTOCOLS:
            continue
        fp = _ob_fingerprint(ob)
        if fp in skip:
            continue
        ob["tag"] = f"FV-{src_code}-{ob['tag']}"
        out.append(ob)
        if len(out) >= max_count:
            break
    return out


def search_udp_any_server(binary: str, want_count: int = None):
    """SW 'udp' alone: find ONE (or want_count) healthy server of ANY protocol that
    really relays UDP (real SOCKS5 UDP ASSOCIATE test through its own tunnel), walking
    the FV sources T1..Tn the same way a protocol search does.
    Returns (pool, manual_tag, source_index) or (None, None, None)."""
    deadline = time.monotonic() + FV_PROTOCOL_TIME_BUDGET
    wait = FreeWaitDisplay(1, 50).start()
    ns = "udp:any"
    order = _rank_sources(ns, [f"T{i + 1}" for i in range(len(FREE_VLESS_SOURCES))])
    found, found_src = [], None
    seen = set()
    try:
        for key in order:
            src = int(key[1:]) - 1
            if time.monotonic() >= deadline:
                break
            plan = _udp_any_plan_for_source(src, FV_PROTOCOL_MAX_PER_SOURCE, skip=seen)
            seen.update(_ob_fingerprint(ob) for ob in plan)
            if not plan:
                _SOURCE_MEMORY.record(ns, key, False)
                continue
            wait.set_progress_total(len(plan))
            t0 = time.monotonic()
            good, _bad = _quiet_verify(
                binary, plan, level=0, stop_after=(want_count or 1), workers=FV_PROTOCOL_WORKERS,
                deadline=min(deadline, t0 + FV_PROTOCOL_SOURCE_BUDGET), on_done=lambda ok: wait.tick(1),
                want_udp=True)
            if good:
                _SOURCE_MEMORY.record(ns, key, True, time.monotonic() - t0)
                found = [ob for ob, _ in good]
                found_src = src
                break
            _SOURCE_MEMORY.record(ns, key, False)
        return found or None, (found[0]["tag"] if found else None), found_src
    finally:
        wait.stop(len(found))


@_requires_isp_org
def connect_by_udp_any(binary: str, want_count: int = None):
    """SW 'udp' alone: connect to the first healthy server (of any protocol) that
    really relays UDP; the reserve then keeps looking for more UDP-capable servers
    so Switch Server fills up (to want_count when given)."""
    pool, manual, src = search_udp_any_server(binary, want_count=want_count)
    if not pool:
        return "none", None
    kill_singbox()
    _state["cleaned_up"] = False
    prev = (_state.get("free_vless_mode"), _state.get("free_source_index"),
            _state.get("free_verified_pool"))
    _state["free_vless_mode"] = True
    if src is not None:
        _state["free_source_index"] = src
    _state["free_verified_pool"] = pool[:FREE_VLESS_COUNT]
    proc, tag, ok = connect_with_fallback(binary, pool, manual, False, pool,
                                          label="Connected UDP", enable_fragment=None)
    if tag and ok:
        save_switch_server_pool(switch_server_cache_key(True, src), pool)
        if _RESERVE is not None:
            _RESERVE.set_binding(fresh=True, count=want_count, udp_only=True)
        return "ok", (proc, tag, True, pool, manual or tag, src)
    _state["free_vless_mode"], _state["free_source_index"], _state["free_verified_pool"] = prev
    kill_singbox()
    _state["cleaned_up"] = False
    return "failed", None


class _SilentWait:
    """Drop-in stand-in for FreeWaitDisplay that prints nothing.

    Used for a country search the user did not just type themselves (e.g. the
    automatic retry after the connection drops) - the search still runs and
    still stops as soon as it finds one healthy match, it's just not shown."""

    def set_progress_total(self, n):
        pass

    def tick(self, n=1):
        pass

    def start(self):
        return self

    def stop(self, final_count=None, clear=True):
        pass


def _ping_plan_for_source(src_index: int, max_count: int, skip=None) -> list:
    """Parse a bounded, de-duplicated slice of a public FV source for P-search."""
    lines = _fv_source_lines(src_index)
    if not lines:
        return []
    src_code = get_free_vless_source_code(src_index)
    skip = skip or set()
    order = list(range(1, len(lines) + 1))
    random.shuffle(order)
    out = []
    seen_local = set(skip)
    for i in order:
        line = lines[i - 1]
        try:
            ob = parse_proxy_uri(line, i, extended=True)
        except Exception:
            ob = None
        if not ob:
            continue
        fp = _ob_fingerprint(ob)
        if fp in seen_local:
            continue
        seen_local.add(fp)
        ob["tag"] = f"FV-{src_code}-{ob['tag']}"
        out.append(ob)
        if len(out) >= max_count:
            break
    return out


def search_ping_server(binary: str, requested_ms: int, silent: bool = False):
    """Find the fastest working FV/public config whose real request latency is
    between 1 ms and the next 50-ms bucket above the user's P value.

    Examples: P318 -> <=350 ms; P400 -> <=450 ms. The returned pool contains
    up to FV_PING_TARGET matching configs so Switch Server keeps the usual
    numbered pool after a P-search.
    """
    upper_ms = ping_search_upper_bound(requested_ms)
    deadline = time.monotonic() + FV_PING_TIME_BUDGET
    matches = []
    seen = set()
    source_of = {}
    lock = threading.Lock()
    target = max(1, int(FV_PING_TARGET))
    wait = None if silent else FreeWaitDisplay(target, FV_PING_MAX_PER_SOURCE).start()

    try:
        for src in range(len(FREE_VLESS_SOURCES)):
            if time.monotonic() >= deadline or len(matches) >= target:
                break
            plan = _ping_plan_for_source(src, FV_PING_MAX_PER_SOURCE, skip=seen)
            if not plan:
                continue
            if wait:
                wait.set_progress_total(len(plan))

            local_results = []
            stop_evt = threading.Event()
            workers = min(FV_PING_WORKERS, len(plan))
            local_lock = threading.Lock()

            def worker(ob):
                if stop_evt.is_set() or time.monotonic() >= deadline:
                    if wait:
                        wait.tick(1)
                    return
                ok, delay_ms, _err = _verify_one_fv_sublink(
                    binary,
                    ob,
                    [
                        "https://www.gstatic.com/generate_204",
                        "https://cp.cloudflare.com/generate_204",
                        "https://www.google.com/generate_204",
                    ],
                    quality=0,
                )
                if wait:
                    wait.tick(1)
                if ok and delay_ms is not None and 0 < float(delay_ms) <= upper_ms:
                    with local_lock:
                        local_results.append((ob, float(delay_ms) / 1000.0))
                        if len(matches) + len(local_results) >= target:
                            stop_evt.set()
                    if wait:
                        wait.add_success()

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(worker, ob) for ob in plan]
                for fut in concurrent.futures.as_completed(futures):
                    try:
                        fut.result()
                    except Exception:
                        pass

            for ob in plan:
                seen.add(_ob_fingerprint(ob))
            if local_results:
                with lock:
                    for item in local_results:
                        matches.append(item)
                        source_of[item[0]["tag"]] = src
            matches.sort(key=lambda x: x[1])
            if len(matches) >= target:
                matches = matches[:target]
                break

        return matches[:target], (source_of.get(matches[0][0]["tag"]) if matches else None), upper_ms
    finally:
        if wait:
            wait.stop(min(len(matches), target))


@_requires_isp_org
def connect_by_ping(binary: str, requested_ms: int):
    """Search by P<latency> and connect to the fastest matching config pool."""
    pool, source_index, upper_ms = search_ping_server(binary, requested_ms)
    if not pool:
        return "none", None, upper_ms

    _state["free_vless_mode"] = True
    _state["free_source_index"] = source_index
    _state["free_verified_pool"] = [ob for ob, _delay in pool][:FREE_VLESS_COUNT]
    if _RESERVE is not None:
        _RESERVE.set_country(None)
        _RESERVE.clear()

    top_outbounds = [ob for ob, _delay in pool]
    manual_tag = top_outbounds[0]["tag"]
    kill_singbox()
    _state["cleaned_up"] = False
    proc, last_tag, ok = connect_with_fallback(
        binary, top_outbounds, manual_tag, False, top_outbounds,
        label="Connected Ping", show_info=False, enable_fragment=None
    )
    if last_tag and ok:
        save_switch_server_pool(switch_server_cache_key(True, source_index), top_outbounds)
        return "ok", (proc, last_tag, ok, top_outbounds, last_tag, source_index), upper_ms
    return "failed", (proc, last_tag, ok, top_outbounds, manual_tag, source_index), upper_ms


def search_country_server(binary: str, code: str, silent: bool = False,
                          want_udp: bool = False, want_count: int = None):
    """Walk the Free Vless sources (T1, T2, ...) until a server whose real exit IP
    is in `code` passes the tests. Shows the usual progress display (unless
    `silent`) and keeps the current connection untouched. Stops at the first
    healthy match - it never keeps searching for a second one.
    Returns (pool, manual_tag, source_index)."""
    deadline = time.monotonic() + FV_COUNTRY_TIME_BUDGET
    level = min(_fv_quality_level_now(), FV_COUNTRY_QUALITY_LEVEL) if FV_QUALITY_MODE else 0
    wait = (_SilentWait() if silent else FreeWaitDisplay(1, 50)).start()
    found, found_src = [], None
    ns = f"country:{code}"
    order = _rank_sources(ns, [f"T{i + 1}" for i in range(len(FREE_VLESS_SOURCES))])
    try:
        for key in order:
            src = int(key[1:]) - 1
            if time.monotonic() > deadline:
                break
            plan = _country_plan_for_source(src, code, FV_COUNTRY_TIER1_MAX, FV_COUNTRY_BLIND_MAX)
            if want_udp:
                plan = [ob for ob in plan if str(ob.get("type")) in UDP_CAPABLE_PROTOCOLS]
            if not plan:
                _SOURCE_MEMORY.record(ns, key, False)
                continue
            wait.set_progress_total(len(plan))
            t0 = time.monotonic()
            good, _bad = _quiet_verify(binary, plan, level=level, stop_after=(want_count or 1),
                                       workers=FV_COUNTRY_WORKERS, deadline=deadline,
                                       country=code, on_done=lambda ok: wait.tick(1), want_udp=want_udp)
            if good:
                _SOURCE_MEMORY.record(ns, key, True, time.monotonic() - t0)
                found = [ob for ob, _ in good]
                found_src = src
                break
            if time.monotonic() <= deadline:   # a real miss, not just the time budget running out
                _SOURCE_MEMORY.record(ns, key, False)
    finally:
        wait.stop(len(found))
    if not found:
        return None, None, None
    return found, found[0]["tag"], found_src


@_requires_isp_org
def connect_by_country(binary: str, code: str, name: str, label: str = "Connected Free Vless",
                        silent: bool = False, want_udp: bool = False, want_count: int = None):
    """Find a server in the country and connect. The current connection stays up
    during the search. Returns ("ok", (proc, tag, ok, pool, manual, src)),
    ("none", None) when nothing was found (connection untouched) or
    ("failed", None) when servers were found but none connected (old one replaced)."""
    pool, manual, src = search_country_server(binary, code, silent=silent,
                                              want_udp=want_udp, want_count=want_count)
    if not pool:
        return "none", None
    kill_singbox()
    _state["cleaned_up"] = False
    prev = (_state.get("free_vless_mode"), _state.get("free_source_index"),
            _state.get("free_verified_pool"))
    _state["free_vless_mode"] = True  # the screen is drawn inside connect_with_fallback()
    if src is not None:
        _state["free_source_index"] = src
    _state["free_verified_pool"] = pool[:FREE_VLESS_COUNT]
    proc, tag, ok = connect_with_fallback(
        binary, pool, manual, False, pool, label=label, enable_fragment=None
    )
    if tag and ok:
        save_switch_server_pool(switch_server_cache_key(True, src), pool)
        if _RESERVE is not None:
            _RESERVE.set_country(code, name, count=want_count, udp_only=want_udp)
        return "ok", (proc, tag, True, pool, manual or tag, src)
    _state["free_vless_mode"], _state["free_source_index"], _state["free_verified_pool"] = prev
    kill_singbox()
    _state["cleaned_up"] = False
    return "failed", None


# ---- AI Engine: candidate collection + one-shot connect ----------------------
def _ai_collect_candidates(limit: int = AI_ENGINE_CANDIDATES, binary: str = None) -> list:
    """Current pool + silent reserve + a random slice of the best-ranked Free
    Vless sources, de-duplicated. Only the download of a few source lists costs
    time here; the timed speed test itself is capped by AI_ENGINE_BUDGET."""
    seen, out = set(), []

    def add(ob):
        if not isinstance(ob, dict) or not ob.get("tag"):
            return
        fp = _ob_fingerprint(ob)
        if fp in seen:
            return
        seen.add(fp)
        out.append(dict(ob))

    for ob in list(_state.get("free_verified_pool") or []):
        add(ob)
    if _RESERVE is not None:
        for ob in _RESERVE.snapshot():
            add(ob)
    for ob in AI.known_good(30):     # healthy in earlier runs: tested again, but first in line
        add(ob)

    keys = _rank_sources("ai:any", [f"T{i + 1}" for i in range(len(FREE_VLESS_SOURCES))])
    fetched = 0
    for key in keys:
        if len(out) >= limit or fetched >= 8:
            break
        src = int(key[1:]) - 1
        try:
            lines = _fv_source_lines(src)
        except Exception:
            lines = []
        if not lines:
            continue
        fetched += 1
        code = get_free_vless_source_code(src)
        order = list(range(1, len(lines) + 1))
        random.shuffle(order)
        taken = 0
        for i in order:
            if taken >= 40 or len(out) >= limit:
                break
            try:
                ob = parse_proxy_uri(lines[i - 1], i, extended=True)
            except Exception:
                ob = None
            if not ob:
                continue
            ob["tag"] = f"FV-{code}-{ob['tag']}"
            before = len(out)
            add(ob)
            taken += len(out) - before
    # The protocol this user usually wants: its dedicated feeds are searched too (best-ranked first).
    pref = UB.top_protocol() if binary else None
    if pref:
        try:
            defs = _protocol_source_defs(binary, pref)
            builders = dict(defs)
            keys = [k for k, _b in defs
                    if k.startswith("EXTRA:") or k == "FPDB" or (k[:1] == "T" and k[1:].isdigit())]
            for key in _rank_sources(f"proto:{pref}", keys)[:3]:
                try:
                    got = builders[key]()
                except Exception:
                    got = []
                for ob in got[:60]:
                    add(ob)
        except Exception:
            pass
    random.shuffle(out)
    return _ub_order_candidates(out)


@_requires_isp_org
def connect_by_ai(binary: str):
    """Command 'ai' (one-shot): speed-test many candidates on the normal internet
    for at most AI_ENGINE_BUDGET seconds, rank them with everything the AI engine
    has learned, connect to the best one and stop. Returns the same
    ("ok", (proc, tag, ok, pool, manual, src)) / ("none"|"failed", None) as the
    other connect_by_* searches."""
    cands = _ai_collect_candidates(binary=binary)
    if not cands:
        return "none", None
    t0 = time.monotonic()
    wait = FreeWaitDisplay(1, len(cands)).start()
    good, final, metrics2, stage1 = [], [], {}, []
    try:
        # Stage 1: quick real request through every candidate's own tunnel.
        good, _bad = _quiet_verify(
            binary, cands, level=0, stop_after=AI_ENGINE_STOP, workers=10,
            deadline=t0 + AI_ENGINE_STAGE1, on_done=lambda ok: wait.tick(1))
        if good:
            fast = [(ob, ms) for ob, ms in good if ms is not None and ms <= UB.ping_ceiling(AI_ENGINE_MAX_PING_MS)]
            stage1 = fast or good[:AI_ENGINE_TOP_QUALITY]   # nothing under the ceiling: best of the rest
            top = AI.rank(stage1, prefer=UB.prefer_fn())[:AI_ENGINE_TOP_QUALITY]
            # Stage 2: stability (repeated + simultaneous probes) and a real download test.
            wait.set_progress_total(len(top))
            final, _bad2 = _quiet_verify(
                binary, [ob for ob, _ms in top], level=2, workers=3,
                deadline=t0 + AI_ENGINE_BUDGET, on_done=lambda ok: wait.tick(1),
                metrics_out=metrics2)
    finally:
        wait.stop(1 if good else 0)
    if not good:
        return "none", None

    # The user's usual country is verified for real (exit IP) on the best few, so the ranking bonus
    # is not just a guess from the config's name. Small and time-boxed.
    vc = set()
    pool_for_rank = final or stage1
    tc = UB.top_country()
    if tc and UB.confidence() >= 0.5 and len(pool_for_rank) >= 2:
        try:
            cg, _cb = _quiet_verify(binary, [ob for ob, _ms in pool_for_rank][:6], level=0, workers=3,
                                    deadline=time.monotonic() + 12.0, country=tc)
            vc = {ob.get("tag") for ob, _ms in cg}
        except Exception:
            vc = set()
    prefer = UB.prefer_fn(metrics=metrics2, verified_country=vc)
    ranked = [ob for ob, _ms in AI.rank(pool_for_rank, prefer=prefer)]
    note = "Local AI"
    if claude_ready() and len(ranked) >= 2:
        ping1 = {ob.get("tag"): ms for ob, ms in good}
        rows, by_id = [], {}
        for n, ob in enumerate(ranked[:AI_ENGINE_TOP_QUALITY], 1):
            m = metrics2.get(ob.get("tag")) or {}
            cid = f"c{n}"
            by_id[cid] = ob
            src = connect_source_label(ob.get("tag")) or "other"
            rows.append({
                "id": cid, "proto": protocol_label(ob),
                "source": re.sub(r"[_@].*$", "", src),
                "ping_ms": round(ping1[ob.get("tag")]) if ping1.get(ob.get("tag")) else None,
                "median_ms": round(m["median"]) if m.get("median") else None,
                "worst_ms": round(m["worst"]) if m.get("worst") else None,
                "kbps": round(m["kbps"]) if m.get("kbps") else None,
                "fails": m.get("fails"),
                "learned": round(AI.proto_score(ob.get("type")), 2),
                "pref_match": round(1.0 - prefer(ob), 2),
            })
        with Spinner("AI Engine: Gemini is reviewing the results..."):
            order, reason = claude_rank_candidates(rows, profile=UB.gemini_profile())
        if order:
            first = [by_id[i] for i in order]
            fps = {_ob_fingerprint(o) for o in first}
            ranked = first + [o for o in ranked if _ob_fingerprint(o) not in fps]
            note = f"Gemini: {reason}" if reason else "Gemini"
    seen_fp = {_ob_fingerprint(ob) for ob in ranked}
    ranked += [ob for ob, _ms in AI.rank(good) if _ob_fingerprint(ob) not in seen_fp]
    pool = ranked[:FREE_VLESS_COUNT]
    kill_singbox()
    _state["cleaned_up"] = False
    prev = (_state.get("free_vless_mode"), _state.get("free_source_index"),
            _state.get("free_verified_pool"))
    _state["free_vless_mode"] = True
    _state["free_source_index"] = -1
    _state["free_verified_pool"] = pool
    proc, tag, ok = connect_with_fallback(binary, pool, pool[0]["tag"], False, pool,
                                          label="Connected AI 🤖", enable_fragment=None)
    if tag and ok:
        picked = next((o for o in pool if o.get("tag") == tag), pool[0])
        AI.mark_pick(picked)
        AI.remember_good(good)
        _state["ai_note"] = note
        save_switch_server_pool(switch_server_cache_key(True, -1), pool)
        if _RESERVE is not None:
            _RESERVE.set_binding(count=AI_SWITCH_TARGET)   # release any old binding; Switch Server grows to AI_SWITCH_TARGET
        return "ok", (proc, tag, True, pool, tag, -1)
    _state["free_vless_mode"], _state["free_source_index"], _state["free_verified_pool"] = prev
    kill_singbox()
    _state["cleaned_up"] = False
    return "failed", None


def _init_reserve(binary: str):
    global _RESERVE
    _RESERVE = ReserveManager(binary) if FV_RESERVE_MODE else None
    return _RESERVE


def _release_country_binding():
    """Turn off any Type Country binding on the reserve.

    Called whenever the active connection moves away from Free Vless (to the
    built-in S1-S8 subscriptions, a custom Link, or a Fast Connect startup
    fallback), so a country search from a previous session never keeps
    running in the background - visibly or silently - once the app is no
    longer on Free Vless. Typing a country name again afterwards starts a
    fresh search in the Free Vless sources, same as always."""
    if _RESERVE is not None and (_RESERVE.country or _RESERVE.protocol
                                 or _RESERVE.site_feed is not None):
        _RESERVE.set_binding()


def _merge_reserve_into_pool(top_outbounds: list, all_outbounds: list):
    """Free Vless mode: append the stored reserve nodes to the Switch Server list
    (numbers after the current pool). Idempotent; returns the (possibly new) lists."""
    rm = _RESERVE
    if rm is None:
        return top_outbounds, all_outbounds
    have = {o.get("tag") for o in top_outbounds}
    extra = [ob for ob in rm.snapshot() if ob.get("tag") not in have]
    if not extra:
        return top_outbounds, all_outbounds
    merged = list(top_outbounds) + extra
    return merged, merged


def reserve_failover(binary: str, rm, show_info: bool = True, label: str = "Reconnected Free Vless"):
    """Reconnect from the stored reserve. The stored nodes are re-tested quickly
    (on the normal internet, while the current connection - if any - is still up);
    as soon as FV_RESERVE_FAILOVER_STOP pass, the old sing-box is replaced.

    Returns (proc, tag, ok, pool, manual_tag) on success or None (the caller then
    falls back to the normal Free Vless search)."""
    reserve = rm.snapshot()
    if not reserve:
        return None
    good, bad = _quiet_verify(binary, reserve, level=0, stop_after=FV_RESERVE_FAILOVER_STOP,
                              workers=5, deadline=time.monotonic() + FV_RESERVE_FAILOVER_DEADLINE)
    rm.remove_tags(bad)
    if not good:
        return None
    verified = [ob for ob, _ in good]
    vtags = {ob["tag"] for ob in verified}
    rest = [ob for ob in reserve if ob["tag"] not in vtags and ob["tag"] not in bad]
    pool = (verified + rest)[:FREE_VLESS_COUNT]
    kill_singbox()
    _state["cleaned_up"] = False
    # The screen is drawn inside connect_with_fallback(): the Free Vless state (FV highlighted,
    # "Switch Sub : T1 - Tn", "CONNECT to T<n>") has to be set BEFORE, not after.
    prev = (_state.get("free_vless_mode"), _state.get("free_verified_pool"))
    _state["free_vless_mode"] = True
    _state["free_verified_pool"] = pool[:FREE_VLESS_COUNT]
    proc, tag, ok = connect_with_fallback(
        binary, pool, verified[0]["tag"], False, pool,
        label=label, show_info=show_info, enable_fragment=None
    )
    if tag and ok:
        save_switch_server_pool(switch_server_cache_key(True, _state.get("free_source_index")), pool)
        # Every server of the live pool leaves the reserve (it is in the Switch Server list
        # already); the background search then tops the pool up towards FV_POOL_TARGET_TOTAL.
        rm.remove_tags({o["tag"] for o in pool})
        return proc, tag, True, pool, verified[0]["tag"]
    _state["free_vless_mode"], _state["free_verified_pool"] = prev
    kill_singbox()
    _state["cleaned_up"] = False
    rm.remove_tags(vtags)  # passed the quick test but did not really connect
    return None


def find_singbox_binary():
    return shutil.which("sing-box")


def get_singbox_version(binary: str):
    """Returns the installed sing-box version as an (major, minor, patch)
    tuple, or None if it can't be determined. Used to gate the Fragment
    presets to versions that actually understand tls_fragment - enabling
    it on an older build would just make sing-box refuse to start."""
    try:
        result = subprocess.run([binary, "version"], capture_output=True, text=True, timeout=5)
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", result.stdout or result.stderr)
        if match:
            return tuple(int(x) for x in match.groups())
    except Exception:
        pass
    return None


def print_install_instructions():
    print()
    print("[93m⚠[0m sing-box was not found on this system.")
    print("[93m⚠[0m Install it and run the script again:")
    print("    - Termux  : run  Ramin --setup  (installs everything automatically), or: pkg install sing-box   (1.14.x is required)")
    print("    - Windows : winget install sing-box")
    print("    - macOS   : brew install sing-box")
    print("    - Linux   : grab the binary for your architecture from releases below and add it to PATH")
    print("    - Direct download (everywhere): https://github.com/SagerNet/sing-box/releases")
    print()


def acquire_wake_lock():
    """Prevents Android from killing Termux when the screen turns off/locks.
    This command is built into Termux itself, no extra package needed.
    Runs silently - not part of the visible connection pipeline."""
    if shutil.which("termux-wake-lock"):
        subprocess.run(["termux-wake-lock"])

def release_wake_lock():
    if shutil.which("termux-wake-unlock"):
        subprocess.run(["termux-wake-unlock"])


def send_notification(title: str, content: str):
    """Sends an Android notification via Termux:API, if available. Silently
    does nothing on non-Termux systems or if termux-api isn't installed."""
    if shutil.which("termux-notification"):
        try:
            subprocess.run(
                ["termux-notification", "--title", title, "--content", content],
                capture_output=True,
                timeout=5,
            )
        except Exception:
            pass


# ---- Cleanup / port release -------------------------------------------------
# Tracks the currently-running sing-box process so it can be killed from
# anywhere (normal exit, crash, Ctrl+C, `kill`, terminal closing, etc.)
_state = {"proc": None, "cleaned_up": False, "fragment_supported": False,
          "free_vless_mode": False, "free_source_index": None, "free_sub_pool": [],
          "free_verified_pool": [],
          "switch_sub_pool": [], "switch_sub_mode": None}


def register_proc(proc):
    _state["proc"] = proc


def kill_singbox():
    """Terminates sing-box (if running) so it releases the listening port(s)."""
    if _state["cleaned_up"]:
        return
    _state["cleaned_up"] = True

    proc = _state["proc"]
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            print("[93m⚠[0m sing-box did not stop in time, killing it...")
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    _state["proc"] = None


def _handle_termination_signal(signum, frame):
    kill_singbox()
    kill_test_procs()
    release_wake_lock()
    sys.exit(0)


def install_cleanup_handlers():
    """Makes sure the port is freed no matter how the script ends."""
    atexit.register(kill_singbox)
    atexit.register(kill_test_procs)
    # SIGINT: Ctrl+C. SIGTERM: `kill <pid>` or the OS stopping the process.
    signal.signal(signal.SIGINT, _handle_termination_signal)
    signal.signal(signal.SIGTERM, _handle_termination_signal)
    # SIGHUP: terminal/session closing (not on Windows).
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, _handle_termination_signal)


# 5 columns x 5 rows per letter ('#' = filled, '.' = empty) - shared by the
# startup "RAMIN VPN" banner. Kept intentionally short (5 rows, not the
# old 7) so it doesn't dominate a phone screen; print_banner() adds a
# drop-shadow layer on top of this to give it a "3D" look without making
# it any taller.
_BLOCK_FONT = {
    "R": ["####.", "#...#", "####.", "#.#..", "#..#."],
    "A": ["..#..", ".#.#.", "#####", "#...#", "#...#"],
    "M": ["#...#", "##.##", "#.#.#", "#...#", "#...#"],
    "I": ["#####", "..#..", "..#..", "..#..", "#####"],
    "N": ["#...#", "##..#", "#.#.#", "#..##", "#...#"],
    "V": ["#...#", "#...#", ".#.#.", ".#.#.", "..#.."],
    "P": ["####.", "#...#", "####.", "#....", "#...."],
    " ": [".....", ".....", ".....", ".....", "....."],
}


def _render_block_word(word: str) -> list:
    """Joins each letter's glyph rows with a single-space gap column (not
    a wider dot-spacer) to keep the whole banner as narrow as possible -
    width is the whole problem with block-art banners on a phone."""
    rows = ["" for _ in range(5)]
    letters = [_BLOCK_FONT.get(ch.upper(), _BLOCK_FONT[" "]) for ch in word]
    for i in range(5):
        # The glyph definitions use "." as an empty pixel. Render those
        # positions as real spaces so no dots appear around/inside the logo.
        rows[i] = " ".join(letter[i].replace(".", " ") for letter in letters)
    return rows


def _print_text_banner():
    """Print a medium-sized bold RAMIN VPN banner for mobile Termux.
    RAMIN is green and VPN is orange, with no surrounding box.
    Used only as a fallback when the terminal is too narrow for the Faravahar.
    """
    ramin_rows = _render_block_word("RAMIN")
    vpn_rows = _render_block_word("VPN")
    for i in range(5):
        print(f"{_C.BOLD}{_C.GREEN}{ramin_rows[i]}{_C.RESET}  "
              f"{_C.BOLD}{_C.ORANGE}{vpn_rows[i]}{_C.RESET}")


# ---- Faravahar banner --------------------------------------------------------
# The Faravahar is stored in several sizes (columns x rows). The banner picks the
# biggest one that fits the terminal WIDTH and, in "fit" mode, also leaves room for
# the rest of the screen, so the whole screen (banner + connection box + command
# legend + prompt) always fits without scrolling. This matters: when a redraw is
# taller than the terminal, its top rows scroll off into the scrollback on every
# refresh, and the banner pieces pile up there ("stacked copies").
#
# A wider AND taller terminal (Termux zoomed out with a pinch) picks bigger sizes
# automatically: the largest (148 x 35) draws every feather, the ring, the curls
# and the face almost pixel for pixel. The small sizes draw the figure a little
# larger than in the original artwork on purpose, otherwise the face would be
# smaller than one character cell.
#
# FARAVAHAR_MODE:
#   "fit" - biggest picture that fits the width AND leaves room for the screen (default)
#   "big" - biggest picture that fits the width, even if the screen then scrolls;
#           the scrollback is cleared on each redraw so no stacked copies remain
#   "off" - always use the RAMIN VPN text banner
#
# Each size was fitted to terminal block glyphs (eighth / quadrant blocks, two
# 24-bit colours per cell). A cell is 3 characters: glyph + foreground colour letter
# + background colour letter ('.' = transparent: black as foreground, the terminal's
# own background as background). Rows are zlib+base64 packed to keep this file tidy.
FARAVAHAR_MODE = "fit"
_FARAVAHAR_REST_DEFAULT = 45   # rows below the banner before the first measurement
_COMPACT_SAVES = 5             # rows the compact layout saves (blank spacer rows + shorter ports line)
_FARAVAHAR_PALETTE = {
    "O": (36, 12, 4),
    "B": (84, 36, 2),
    "L": (150, 88, 24),
    "S": (253, 234, 174),
    "K": (242, 42, 85),
    "k": (141, 26, 38),
    "T": (3, 181, 173),
    "t": (14, 111, 103),
    "A": (245, 154, 24),
    "G": (249, 179, 34),
    "H": (249, 209, 94),
    "D": (195, 113, 15),
}
_FARAVAHAR_DATA = {
    (24, 6): (
        "eNqFkUEOgyAQRfc9hSfgDjMbF5i4KBfSKqVNuqVu7OE4Sf+gKG1pTMjLjDBvGKyUqn5W8E8GBg14iW6qCf5KbfAXpuAfTaEoX6eq"
        "rJ1rUbRQvNoabs3BWz6jFSHqiQ+0KJY7ZTAb6o+NaJ3lsk4GuBAGcIToHqf4suhNsPvyXTSeJexZQyPRqA1SwWgwyWDQqZN0hyWz"
        "9oyI6b47LGW1CCipBG5rNOn0kHh8hQ9WMJYgx+2CZIxYUk5HSrVRCv3Bn5NXtAq2ieP9pAPpFZ2i/Ij78//ev70AcQ=="
    ),
    (24, 7): (
        "eNqdkkEOgyAQRfc9hSfgDswGE0xc6C16ClGjrTHpCtnUw3GSzidoNdW0aUJegBneDGgiRPIxvJ2I0VwZFrNBkLedzL01JL0ds4ND"
        "23FJjrVjnnlbAUPGMgdtSwXvSZ49cvpPexcsqynlbgt2G8gc8ayXiMr8i5bPCc3ZmrM7jauWKxRalHoHxTAqPAnFIu/ABtgLKU6W"
        "0edoKTQJzYV79N+gulkjrebs5gwu5S9QrRhQ5DQ5qILUoEYr9O4ZY/0OsQiKqNH3DDzRdw1RgMNyxm8QUuIJvUX/wzeLhZW3NxiM"
        "wIVoQVhGtdoLt+MFyioVdg=="
    ),
    (30, 7): (
        "eNqlUlGqgzAQ/O8pPEHukPAgQgQ/zC08haat0oK8r+iPl/MknVmrbV/1USiEIbvJ7sxkkyiV7Kwp9gZwLAGxnDPXPJtio/Mp1kYj"
        "zPJkv8HzOuyztISajTtbsrEFOOTGwkzxZIopVhq7lmp+Vf4VnTBeFAwElcJhAdpTBis1KQaDsNXqDt3PZ96o0qGGohuHPqNH2Hhz"
        "h+A1X41utHsDYW5WEOY+1csV+wrMyb2aTQftUeFRMfhFgQAEHcTryCgo8qwazw5Vx1cIG7mOKqoVLjp9u7JVK+2FSCiF/Kzc37HA"
        "h6JpHj/vFgh02ctYCGFlesBocRDlVN5PmY2mM3z+O9pZmqVozlIe2yzzqLibP795WLBS9k/bG4t5V24="
    ),
    (30, 9): (
        "eNqlk01uhDAMhfecghPkDolGmpESiUVzi257Af4RlZiuAhs4XE5SP0PS6YyGQa2EPsWJ42c7JhUiffJ51wGlIeRq3RmE8a6V2Ybe"
        "ZOnzALdf8kpFKu8m/e7drLR3V0V7k6C9L/VGLjDnTLHzv+RYscmoiurjRCt19q6QJNtCgnVqpML5DOaYGPVHiwC1i+hSo64FGKXZ"
        "9HJlULqkRCSafcoe7x7XSFAe9bKDzZgtTCs2OEtKnxAecVBGVOsKHbAhGUbPrbn30wil8XzknOPGJO2mMdlfGVBCyfbis+aKw3Gr"
        "6UoFFEAO1PYcIW9Xw+UurUt0kQ/X8hiUw7NQt/aIk16nKgnD0WLqGkFHNVDtAyFGvFgFqTKCTccH6mUUFmLJ7tgA95wjHmNhwOS6"
        "mgg2F8zDghlv0aer+us/89OZ9e2gWgg0VwWwOcngQs778b4BeiPQPQ=="
    ),
    (36, 8): (
        "eNqtlE1ugzAQhfc9RU7gO3hUCSQjsQi36LYX4C9GQenSsCGH80kybwBDQktSKRL6NBjPvOcZ4KDUYffyriBGZ1KOEo6aaflC2jur"
        "sYxI8JM+qfZwfTzTPiuuf9LkXW8S7yr95V07ufBuOOIB0MCjwFH6TgviolUsUR6/GTHhlGylTsykeKEEjaDJaPv5TwN8LKO2yO6h"
        "A37Z3BObuSaxdznGUGp2NCQcNcgQDKn+Q2jBovEgvtnMpgfptkIXsLigMhn7AGwWoQLejhWiTVRr3nyle7/x/GCdsa0i5UVIJEXc"
        "AouhDiZ7mkfNc8I8K6yWAnSvQFQgkuzTLnI1G8kDRl84xH6uHQsEyWCjBqwyr7+XHUZQj1PD6wfxznBUh1YI5NahFQP2VRFNaY7e"
        "8YGIF4ueCs7ytYR/Qh4w/ifQumad8Ur9G01z0Zg="
    ),
    (36, 9): (
        "eNqtk01ugzAQhfecIifwHTyqRCQjsQi36LYXAMxPEzXJysmGHo6TdN7EuIZIIZEiWZ9sbM97zHg2Sm0ejtH1QGlyBoWPP6RH1+k8"
        "xjFfibUYyZryXnFUq4mRmdFV+nN0Ls29pW/asY8d7/akPOx7LYiLIWPFy1c2uiZPeZayYmtULNvAYw04Ta8ZQGrVBFqHmaFBDhxt"
        "eZZNuboAJX2M7pRxkXrN5w6oz1JjHuppcYLplrggvWQhYCjwrVAedcHqrU6RHt6w2K3nsDhy3rLfX5gWq4LLVsc3bHEfQIJKeBGK"
        "dE1xZ43tJv7ZDFhXc/sdrligAkqgRdSmSAN0DDH97/dmGj1xlmLMDy8ClEFIJLu5X7F2NbfGS6J32Cn8dYB9FpJ8Sn226wBZWni+"
        "HXkynoi3QKfopUY6KHQOCi39cpWcGekmzkATIEuHjQFHWqADTvSOjvbJJP8e9pjVSEMFlAGyrBTjSNON+JcfjD+4XyQX"
    ),
    (36, 11): (
        "eNqtlEGOgyAUhvc9RU/AHSAmmmDCotxitnMBbEdtm+nMCt3o4TzJvP8VpdVmapMm5gsKvPfxALdCbJ89gy8UoY7vZW4I8g4X9TzS"
        "7bN5lrQxhFZ8DL7XBM/IryKktFODP0lCpSSQU695s0IHhcJQfC8pvjMJGSW02EIb5NwBGXXAg3F+bxXY4iwo2X73Scio1WmFHSGf"
        "GttywvL7HDVggcS8JoDFiAAXW/Ye6Yg4OIBylijEOaNWB5mvnFrHhAR/oFVLrEGa2xxOL0PFHLPk83Ea0qXSFBrvEb8W3zCF4a3E"
        "2UzJSFLH3j4CDelgfslGVYbHQh7PGMFBi5TGNYgS8zbaLtRIdxNOLu/frLtDwILnIUKFgIcr0gnyFh7foi+jUSyzHDxDOflyytYu"
        "S9my5HQ+sbOEg8DiUfnivvwV4vyPVpOXg2GRjXBcfi1XBeBEbkrOGizUqhcu0/XngWrtsaIed6YXKpSislmoPr826Ojh7OQ4rX7b"
        "rUZSIQNa2Hzz6nCuHHDkm45Wh3XyFoQZ6bof7mb9j2DaYhx83qYI/hYs10f8Ax8Vd80="
    ),
    (44, 10): (
        "eNq1lE1ugzAQhfc5RU7gO3iEBJKRvAi3YNsL8BvaKCQrhw2X4ySdN4BbUlqFVJHQJzOD5z3bg/dK7R97BtcAuWFk1gevxKi1/YGr"
        "jfcPF797dg97uoUs1VLKoqkZ3HtKgyvjKRczikM8OHfgcAOnAkc8ydmXm6sVa5cU8q698aiwenBdyFaqlLOdWpgqNE3IgJbsa+2J"
        "ww/LUrk9sNcII+xTFevJUhbza0fB4E4BYlpNaINnzXF5NNAqkhVoj1+nGT7MJkBrEpt0Ee/0BaOeFp4ro6eP/yg1owyX4neu1qft"
        "oImTJO7EBkHB0dA0KkzCI1RoxlrsqAAyjypMoLkGnEUSfl+SoEaiR2J92gKikYsQ8OVFrB3Fnzc+elYGPTC3FX+EQAnky3UKapSo"
        "gHILeorYXDQfmJyfvHZIbCol4vVyJRmc5t44L2H9X0GKpiXWm9HCdQXcElRJImzzjBo4I1H57tyuIdaa//30vVwyssVKbiSOnZRc"
        "PMb37NwOLbZOEhck+tDPxb121q+5mVYM5/Caj8oz5LUAOk3PVf8Es1auMg=="
    ),
    (44, 13): (
        "eNq9lU+O6jAMxvecghPkDraQWqmRuqC3YDsXILRQMRKwSrvpHK4nef5M29DyZ/rmPUZCPzlybH+Om7A0Zjn71/ptKijD+mIFe0rv"
        "4ImXf5P69reYLadiQbERnDZJ6/NEKrv06msgdW9JtMQsFlOHE6e/IO1CUrQAcrsRpZFt/aceivggO+d16+u1bCixVDQpQ9/bxenZ"
        "FGnU+t2H7awqkto+Ea11OhJVWFk6soBYx3fLU4WfqdTbr/E5xSkkybJeCc62F1fzSvatZKIlmQ4n+uFsF3IUibmFC1Y2Bgq5qMck"
        "LOBgZcDH2GKiInK7FutA/VmebS/cJQTwbV33LGmoewUE7QZpu8ex0lyD/CXWEzSZXJwSwYqGMsmgd4UihIlVZYQiTyEJPKwzj2ZR"
        "ce/tQGNrlKBO+pKOBTVkBFVVkt0Jd6xhvNDvpTDJ4/4KhG6T7K5Jre2+R8WxRIxb0+UXxd/FhiYnDTkIKh50tUVX0ky4L6iGPuBQ"
        "7yTiMKRS5DPRoK3QUZhYDcfcLKHu4UUzSPrkEZChG7zOpt/5GvnY8iigqqsMz20G6QN06eHwRgc5r8YE+yv4X16zivRvErcRD8BF"
        "vyZjXoxMHWcM3mNzPiTw9K4nt0H6HCelqFmF4w+McGkBN0CX6vDYop9oFxvdjPs/ixwLLlBvBzgFDxgcBdPPsv8B4gt6eQ=="
    ),
    (52, 12): (
        "eNrFlU1ugzAQhfc9RU7gO3gUiUhEYgG36LYXsA0JTdR2Z9iQw3GSzhuCIfxEjSKlEvqEx8Z+8zw2G6U2Dz6tLwFD3dso/rPbt/6g"
        "k2V808NLzZ+3B6VWCeOUvLc+j6n1/j1ufRGzGjvIb/1ZsXCTMvyORx1JB3DsO/kH4Z8J1ECDi+DqnjXnEedRIWaImwa5FbQD0tbX"
        "KUsvJa2AHON88lrxov+kEtgXsbgPWJrwW4UknOYk6niPcukFV5pQJBgHFIAX/If0Br42KbSqFJXCKNA805ab0GW2dH27aM7kvOU9"
        "KbW64oRy/3peOnsCdw7xGrI5is5ANPXdb0fYwe2+3DyOgaQhUw1ZWfQeYv3HSXsUUY9O0ILm9QkIJjQwwSs+uSWCA4440g1xh40z"
        "jmGuAXmGgwIcQyJ5xONy3aNBbw0MMYHUotgx3lUUKWp2MngVdVhcZDhpZtFYpAg/dqBZghWSrqkvYl4eAYeMDS35keF2YzjArsHc"
        "7f3CjXK53XvBD/y4AGe4YO/O0oHmMRdEitxJCpb6BDnVhRPMXylcE/AhD3ABVmJ0E5v02kkHBudaOvpNsqF0TGhKhyN9HexoZfrV"
        "2KRXhNeybVLaT19b8ld2UuVyXIFLxGbVeKuwkluojXEM9558hnvbhqlk0vI1d6/8tVQEk/QVtfwiSITAxwATIE0X4LXYqsezFHKa"
        "X5DEPCcxMgiRMjNQIzeqvZXpFD254C8H4rCC"
    ),
    (52, 15): (
        "eNrFVstt4zAQvW8VqYA9kAggARTgg9WFr9sA9XUsOM6J1EUpzpXsvKGonyVjvck6gPFADunhm6/mRYiXL/+utkwUgdytw7v6hkd+"
        "Pc7KHUDtQAwqTfwyTavjeNzsEhLuCQolp9BKNbn4PNJX+wZKRQSySl+tkQfaHjT8SLJLIpgXMRQxyfYkewcclZjCh9g9n3qHl0sV"
        "XW0N/nVCjjTYsox9bzVducS3hI0MspOie+fdDyTLmyAOeULPn37TymD1ASgk+d+pZErdgXAnEwSGoMK2Sn6K+gnUuz09n4k9vE7J"
        "kSMv3CtBkwTWBqtPEHbylWRS9HCS30OdnIUQj5AP4LfpCkQDSLGuYCpDkHQMqyi/LKqVw8BmdNhecMBbpyVM43/s1gmtAdPwXFhL"
        "qnqmxcj5jgJyQiNCAR8hXECX4gBqRuhkOo0H55NLJZ6bQba1rZScKhghi2+15Hc18+NZFPTxwYKu0+m6bWz0WXESk1UQ2RU/1Agj"
        "+8GwpkFxlUY9C/MIWLSYFpa2cz80XKc4sIAabl78l2VrB94Zc+uNonslOLMJbIwZDHRYtXpSxaQAuVBwM99KiBr6CkAOyB6GMwr+"
        "k3voPPgXrg9AE6u/06dm23ygVm2FnI0uhGZTV1oY2QcXVCJcywFmC/x3b+1gfiWLeIU4wXofsTiA3+KAr9hopnnzjfuQewjGHL/Y"
        "t9k3RgVwAE5f/mByD1mU3QIsdw58bDnEPBgY6fU98cNTS579or5znPvhCUOKnmZ4NUA95FLDjYBnFjlTxW37ov6/EX2RotRFxCs/"
        "Ovo2zJOX7meAfFiVA3CFnVWYy0ZF7XNicDuJIySlCKNshhXXgBu2ftDFqgwV+8+/P0RVlPk="
    ),
    (74, 15): (
        "eNrVWEFuqzAQ3ecUPQF3sFUJJJBYhFtk+y8AGJO2an5WhA09XE7y5z2MgYQklZJ8tVL0NLbH9szzjMfkJQheHvo7NltAnp70fgTJ"
        "sbEqvQKN0i+PNuf8t3qwp4dUwG4E6o04sd/Ex8bEcEf3KlTtoLUjB4k6NpU+B5smv8v990Dj5MQnozbHpo0TnKFIRbhxAyV4aVKe"
        "vyiX6VpGtUC7luaWDM2hGFn7BSSQBwPXKh3Cv1c56hDNRJoFuUkkIEr01UvuKg36BPIREomeT/17KCALb6k4W63/CEQC+TpxpFQY"
        "sKlIbTo79FYLW/WrhP5WBVP4wG3wmT6ZALERVuTxHPQcxr5sYXSp72Tu0sonA7gtamSFTQRKwA705bwbEu3AIjhaxNROn5O2T5Vb"
        "arLbdY/i2+5fhG94fiatkCuSDVt0Xocugx42WQKTKWQNMi5UDt6YSZrJJnDw0tjXUFJe8n2cm0fIUcAnmif0nkAXq+nKXHRxt3H0"
        "EvzlYYbB1JkDHGzDbNn9FuTk+iaTQvbKVSmrhykEG+spULuG1GG0iS9sbGFWCShgdA2eCIaWqwynkl2TwqHp+lAU0GfBe7kQ1n1s"
        "sz5GejY3PJfMkjTffLSZ6VTAGZuFy/4WIMKSDc8QCaM00slRy9D2N6sooS4UwRAKJ4fDibVnnwFvsFVxif06w00AgwlmAuG8SZXw"
        "TK8BvIPGL880qah8wNdeeoe0U5ELRvNNqLwto6U14CK/dJohfT2amdEt2Q/0QhHDCWh3DGYe7hfXrPvDHE6ZUN0L9KUBc1V08yIx"
        "UDlAmRFw9+Z2AvoWpT1DIIz3A6nz5N5+J7gZhA678XYfoZw3r8OSMhctcElWvC75nGBRzCJEWYTbKEIWhy6VSz9AFSrzWuECDKGl"
        "zRlW5R2WGk+EwP95frOqloqPyKF5QNIeQFPLROanB64NZlruYUzBsa/oY9dPwwJfqLFNqKe7lW63n/USlSKO7OfLaA+rO5SkDs08"
        "QDHVvVYb3MyKj4XE2cXuOw7ONyRYD4+OFttJifqpX6h1EDqwYKJPcBc19IIsWSRI51PF8JnkU2/fl80YHyZD5d8pPda5cZMq0A/9"
        "gls97xsAFitHCz/bDJwrggH4AN/7Po4SmF2mn/vEPy3+AcQGusc="
    ),
    (74, 16): (
        "eNrVV01uszAQ3fcUPQF3sFUJJCOxCLfI9rsAYEx+lDQrYJMcLifpvDE2kABt9TVVI0VPY8/E9jzPD34NgtcH/671PoivtRHJAtRC"
        "vj7+KC8/6laTEJRrSGp9rU9rda0LBWektznD5gj/ixVBKcUdtHHyTK7jOsnHUkjySZDfrSLprGJIfM80PMqETU+SIJcrmo5oul1B"
        "lxBsoGCoJBhLnomAM85tkpAIkASZfCNIYnhKQxMTbNZ8+XzlwZ3PDDkz+OYUe/BwkM+TAEzFlt1e0dHblKRLDJ8Q1fk/GmpwdOP2"
        "HtoGlJWCTCqwwLB/e0YCTIDoR1zrYIXUj2gOfBwxx1lSA+xtA5pYIEEINiIYwh6F8PDgTHih46lgGkoP/dCkkMZg53DkMhyDWFrZ"
        "LMIlQvyAFr0iOCA4NIC5YSJv+GoUSijXHFRdM3H68oubW2d6CKXzaMrzfrjooJsjyreIklxSg6hQLZdBq5Q8xPo3sE2xSiqGWdND"
        "jeKjoS0AGsZ30j3k0FoJJfp9IjAzm7LOZHrl0R6zu9Vzp2doxYznDSj5AnVM8bvkNKe/AjSmNriKZTinZFfPUV/h3KXlS3SMMFQ4"
        "cudBOpxjqR3bdRKMIxq2kUAzcYTXXmITVpzZRFBR2WJusG+Y+mE4lJqJLRlyfwkGMEtzm35K2JbDNFBM8aiqEkkI9QK6bI75XlFh"
        "QwMoADkg8zB1xG/BLiXidojZw0RY26LrFTv74UL/OCGY/3vzTDo/cu9gyW4tcsvkMBgA0TnbvIg/7j7KhbmWS7Q/BAqhuii9IErz"
        "yEV4Frk2l/kwv0DiqOe//dohGyYncMA9uwrk974NunrCfzZ2GTUejhTVpMlIe2OifYbzuyBDFFYAgzAuJ6CyIDvjkvM/FN1S/b4L"
        "Z5GfK24X+KWPrI7vQrqurLkXAVrfkLjasB2nlp4rJYUH7fOwlq5cMekcof1upS3Jf+zL039KcMKFoAJdH3ee24bTvU2V/KwS7GBi"
        "W58vG0c1eOHUgeiWtskLqQ3l33yMdwErBxFKLOAO3/3lVig6/D41kLg4nQA8PPlPzL5ZHIVc2OAvvkgmWcE9MjAVwr3RMk8AD1nL"
        "dq2QnfSzvt78PgC6cdzp"
    ),
    (74, 20): (
        "eNrVWFFuozAQ/d9T9ATcwVYlkByJj+YW/d0LEENIiJr2y/CTHC4n2XkPYwKBpN1uVo2EngbbjD1vxjM2T1H0dOfn5HbR4uQKlV4B"
        "p/TT/Zfy619bZrVAbcSAHLDS550HdO7TZ7SraWgey2yxNYXVC7F1/2pO7mheBSBVRotN6HBpO3QD2MP1uX6RvhcZsAElPeQ6eizz"
        "q0iMeF/EJ7dWGh5GYC9EqmORtrH4On9tOZBesEHbLaBJLgkgrHRKth4m9IWHlG4VHrbPsvi3EORkpGJoaIFywtwMzNkAbPtIRXrT"
        "D7b7c5rzIgR86N8S67CdLDhIFvS4dOD0nRaiagzJlQwpQQBhRxofjYAVtoNDcGc6gfMR69jnzZLuTc9t38LsowIBsH2jonPYKcbR"
        "nQnAQuEzMwE6GvRSWg47ZttG305pNjNwSJAvQN8ezGVgqUI0lM/da4MI2UMakfaRKmhJLyfScxZdt/w6fMly3yaU28hgXwhs0DML"
        "O7MUCZNMwWrJoil7qomVh21LjGjO4m6Oz0qVAoDUNRLz20u3FUccn7Ft1Bfn6KURvOvOBGqm1NqmZjioljf5o2YhWyjfYmPa25QT"
        "DlQ9x7tdxshWMQ5qrHuxj0oLKOCVfHlNKqCgb7NIDQXzQ6w9EyOiqX7HCpFo/60N+uyN2S6BStfBBIK9ynbNULxNXd46k5nVnw6+"
        "xLrTMws4YGW0KgMwMOmEEh2+boh0jJWXPkJvHSTfhoSsEhSeBKWKBapzILnp61COcQdANZojDvNC4mcHqK/btB6mxGAXdwuveyfM"
        "0Vx8kmvruR4UMlmEYQ0akF4aps5LR3AuezXPrBGaHlSAqTY1bNNIJyCO6WQY1quJKK/a5AWXnKnXE1NOdcAlAeaTJkxdTxBMhkZt"
        "NQhrjJ4+L4gehHcRGU/3ekLF1CxlcDIh/y402DhHhGge0rWb4JeByWN6zaDGZ9+evLfjE+afxR0II3VlpG8cyTgGo+HnyHT1M/A+"
        "m/r71z7067kv+iG9UpartTI+Xi1ikwc7mygPje6kImHNSvzgAsl8pcyF+k+sZQSzVmaqI4KUkKES0ubvTrue6btAgcAjM2vNZKj9"
        "lizb/ZsEUF4qw5C9ZnLVPq9SldN3WO7m/96eV7zzY29a1b3WiJsaxTj3K8JW1T5LM39lw3ydhQ7bpoPuM14wHBhzDMYwW96miB92"
        "j/KnNB6AWKhde4FWvoLXzBT+H9Otk7O+2GN7EwVeYh9JR2ZDzLDHqxwFfholrf/ptDYmcFSLmHjO/sC8tTdoJAKmBACTg+uP2eGV"
        "Q2pA3lbc4TRRfA6N/qm37dF/uOFNhUdDSrwStTE1UROb0PZ+zz+PdzW9r44FAqPgruFlIZxsq/CaszYxgGA1pfd7/mb5Axn1ymE="
    ),
    (100, 21): (
        "eNrlWUlu4zoQ3ecUfQLdQYQAGbAALqxbaKsLWJMdGx5Wkjby4XKS5nski5KdON39gf5BBzAKLE4qvhpJ/4iiH1/j99afo+ytb2P9"
        "GTln+ovI/PLXMdpmhlSFIcMaeIA0yrC1nk+rI/XWX3RiWip+QkYVfUcoDXqZAa6KFcBcv/X9ujDYahC1xqgZqL2ZmTkbYLqBea42"
        "ZjZae6AeyKvSwBQq0t8R0IM2mFRZ+tZP2hhWBwRH4NukhuxTM+UEtga5wIp3ykDZgbQgZEetHpCd0HdCq9ffDtY9yAS4WsDawKUn"
        "INoC6h6g39IEMSCFwzOKPkK4pSJAWpCtkBOs9qy+XyS1NqsMfM3GQLDdlGgZdiwVjNn68Vt/BJrnpVUeEDmPcYZMZFr7OJqTE1PU"
        "6ptC2gKvVq+cU9canr0xfUeQQSJAnygXf2mWRPOoHtH8YpC6tFuvo98kfYFlefSMlCA4b51+QPr4jz4+J9oTJMAdAksNL6g2JFAe"
        "iwPoIyiAKru9Y/EDS4yw6X8S7QMy8NDp57j8Arq/L0GhX5CCYNooFPbofE62mMcyggVFX5jQsocIH5ImRygGsnUau2TZoEWyhUJ6"
        "m0rXCPyeWBYfamJPLJsuWiRDYmSZVkaFF5BqpZyLNtnGhbT3XO+ODAmKxkR9IIZ8bTaQLQeCfMkHG/RIbzx0wICQBFxoo6POn2Da"
        "lmZ0B+ypil/QGwnF2EXFC6PZVPiuMKNBqdhK8e0Iy0csBUvSqtxJMVe0kafNkXA0WiUqSp26bN6kmUvQO9jzDjDX6NumZvKOy4gN"
        "2KsqXWubseXnHUslA7lfkZSuVeG7NQuIlffpS7JQ/paGCNJioM385Hpl1lb4bqsS7Jcvvpb6E1k2NqRXIj3qk4d5uYs02zjBoVmf"
        "AIOUJ0/wIYBToqAsBbX80aEs2OvSYU9VkNwpalz6MFXbRSpkS6NzpPgGa/ul4qnkTvTL7SuQpqDiMVrkTpYgWpd75dUwhoYkz3Ai"
        "4Fz6qxi1X+G8I1ojLGIAWwGIHfqGBH1g6Qo35T2D88bMsze0Bnu/M5l4vzJ9IzQ4MtRLbO8yRhbDTlAAtXDDlAG1Jpf1qwRSJYhP"
        "qO3j1BmNdUa0ehGjh5A95u1S1qkJEj2W2cPE/oaQ8NCJO/6A8McYeBPVVnBuohbUTWBrKJmI11BPpRZO163Vg0sP1BGI3HZf7osW"
        "uLReP3g4t+PGVDSvijVG3ZQCIYaWl+MOWeIspTtGaxXtlV+BrS0Lc0bfrgRUeQpWuZZlSyUD2tl+YLmsgwnZDVidQlln6PgCmBmn"
        "O7pvTAX6nP6a+Clk6XMHMRJuNZOFjmfZeC6VHRCWEc2KlvMCCN1ZmRMXp3n8oE+C00tfjTjdFnTf/EGLlfhh0HELQlUwLVv1Fk/r"
        "X3eZamyFKinHenUx/yAtq172kUzW071RdBQbEjeMMGIKNNIpV8JiVJfz0bvJti9MllGiwr4+W8GTVu7q1oHQpwZxaDr+IfYqpqPe"
        "4GeMAwMIt5ryYvlx7dgxV0tZRDTlR61US9EC28hastRVUGct+DEQU3V32qViD1QsBqgoG6F/9Xrj9NxBzx2XgxzUep4XmneKOfY1"
        "ovYBK27LeSNGQxLhilEOwBWBvXJUJt9k4IhdJhoeiyCkuybzTtigPmvgyg3C8BbslizThB1FuMYtq2eCRNzlViPQu+CTE742yWFo"
        "ub3IwveukN+mJSRce4fQTUocstTp3ZRG9BxwrlECBy28q8k/ubE6JbcR3DBaO8LbZ4doPu9bTHGjz6a4XQJbPI7iMANg37GWUozD"
        "hrxKhbIrcQnOV0j5K38nDgQDbkrpAi834EPOLtUum3rUnsr3KfvQ9wjJ3ZRRWYi/8lv4IM9dVAKLFvuWhXcbc8ST3BAGKSKuyDev"
        "IGeMnjDARHRAX2idtKsN8MR2hlImkCtf1/69txz3L0IDw+uE8O12QIvl6AFvBqMD5hVIDLbyKtBiHi19EcwyzaZGnxE40KF1K5TL"
        "AydssJd/LbSLaBNdAZ/rcBXqMpEo0X/lHfgvAH6K+CeDL49H5a+AXaqkfJfZr7p4SCsDyIktCeUnCcJ9CP4IImeplA9adp0y3mRi"
        "99Egw4iynZXENdL/wkslbvUwuihdkmzmzrhVI6RofxtlZdXiXeVsXy7XmIKiBa0j/3zDC0YdwwNAWpBTxju8WXtIJJQ4GbSL83eC"
        "XPQ/+iQs9ouTT8xrKFKvmbzv4EoZStirvEQdAflZ2BF1LFsT+k5yzTGq+V6v7I+VrpZyN3Zkin392AC3Ci3eAu0AL4BRNl/hdtH/"
        "R3qb/34CcJIvcQ=="
    ),
    (100, 26): (
        "eNrlWkuOozoUnfcqegXsAQuJSCB5UNkFUzYQvqlE+YyACVlcr+T5HP8wSaer33uqanWk6MrGxlyfe31/zvco+v5n/H4M5yj/MTSx"
        "/BUZcvmH8PztK2Dag4wF0ChU6yLvYBTqqYh/DLtEkX0c3ZH3WCF9eU0YFSy5Iq0EyRRU16xQeIpM4YnWJZPEePHCBYrZbgBrrMhe"
        "REvyLvSarwnmQQKbRMHSFoAQOM6AtUZrTFXrBNAGqee3AL97w0tv6vHxjWP3qB6FtC+9JKSDSBWQuSI3HNYJpE0VGRP17ATAG+B6"
        "IZ448h0Q68TbHZQrMmPyIF4O1hknfiYC0MpaJmjBjEplJi/AdgLeo0xpVY0lXaE35hZ5rfTojtDfMVJLTeJFnVIL5dvhME9bgRZU"
        "uFStHmhql0VIw6N+gJsaSaDgKzd1grc/b14U0gtNY/5mzOX+TT2r8awiySVQX3kiBWRHa5snjz3/a0NKFaxoJ3G0exjLGggfAOlJ"
        "wwfNBYYEsgc54qRf6fr/aEjVBhG8tL9NBkST7fYpKUGw1Tb9CSFq7b/jYE2g3VUBnyc2yt4i9qLu95BRQ2fIrzlSxQlklNxJ5n9i"
        "6GdkTJ9BYnD5ILq/z0EhldD7qDDR1z6LPk5mBGhDUaruNnpCGhj0Dp6xpt98QLTk82xJ6pTSc63VgGvVOqhRW5g3yEpAdpB3i9PZ"
        "gNBLPDp6K7LDvCkRv/raRwce7YNb/SkQJB3ZkNsnmLalGp3KwuQcHxUZ2VDi/kZrdsWpZZi9IA/UgJ/oEJN3UBqSWigGanBRS0tu"
        "5daJvARBOg733UD4RgPUAetSax35rCvVvA5K0rjWHJcYiE133K4G2JXmDSpYX27MlDPCBp74+UFM4Emdx1Di3EweyUH4ta5MzT7Y"
        "bR1DZKMJ2ei2lviBAd2dsJs2mkIFw8qI0Rss2mAyoasBncfUkyYrnQCEEUqD1kJQRShLmSGilN5bIjdQz3Yh4TwKvgml/0jmlbRk"
        "YIvsgnC/BKdG/lHL1Ox34ulDmrFPsSglmIDAuOkWLJzu5uFA+mjAPrsB2CnfIARUZKKVd2ddn2aoQA1SIaQZdWq0QWoEfcnderFj"
        "Qy9f2tH0fkCf0sSzZgeaVH3yTB3nMYc7oZBrpAjUJgOTNKg1ZYApIe6cpCnk2pGFfCk8EYjxXMggNDJhc4u84iQCwXJ+Ja3Eve03"
        "R12RHt+fYWEqZ4nYoukZwXsLciPhAHR9oAJgyy1IBbwr6bux6VbIntitw3m1GzAEImYkxUMK0VWxCHx4IoyIR4h4hlKMQP4IBdDF"
        "A0o82YCNePk1w4ZnLV92G82anVcvuMfH2YJMaTq4/UmWeBbYQQJGOY8UdgHTvbUQtwCbrlSXkEAqR7zIepaaILI2Eo+jYJh2ZkyZ"
        "ce9ekFrqEPNIo5AVS1l740GDMpBAE0dn1ntnoCbsafJb1J7Idr0P8JPZeqeeuFGufHWLHmgsEcTsN8jyNsgG8yC3u+nDFBuD8p7Y"
        "KiU1YcDkA8TMBS6I0c8LruSSq9lxNTvZLOIV153l9km3xyoDibRY0UgPwHTg4QSmxlzbCldVrORqlYCvdZIeWjxLddTmcaZn7LGl"
        "sF3xsQsdgrYV4QAVoHZiP3K0oMXhBpgW4jijW2M/MyNM120xedkNJi/flctRvsZnA00v4jSfcK5y+BvFGVsRmxKWMK+NWMAsX7rl"
        "HQfZ1lQRPEOcvGBXlMvJpiuX3Ub7vq0B56IlaVEb3OHksxvIzj2b9WTWc6x4SLpQsL/IZKEIiCZYPaacaeZlEPBRnWYZ6BQtyRgG"
        "hlPY5Wk/OVXkG5PbwIiBYxF0/ahfigMzum2CKbCSbWpt7QBZVTDbK3uuWxideZ4hzooyZWgk+HFhQD9kYum/TjwqjrUh3NZqlHZ1"
        "FdTM4RSW8OvwjVt4inq8UYliKYUJsXMfyf9UnrBlhCgzZGZE7mMy6YrhrruLgu6E0dWUu1WC0QYbebQ8xTrB5e2EDU6n3IblDWzr"
        "bgsi70mF6LsBYRw+J9KE/lxqhryJu/5QIZ5ssJHFk+56v0xonk9xq3icnwjuy2tMNWpMvPdgNZnh0STcvZ3zZGfnxLpSLuPK7sEU"
        "7VqdxvnLgSH5qmuSb5932VlJSzSGwiJ8Q7x+RTB3NtdLx4iFo9IEuycQhi6MVd5BzvqZbTF0YUTB1sksRO/MOJFZD2s4vBQY5Zqj"
        "vwFsHDEQoNojKSLhwWeFi7o8UauljWFQGXWOa9SxqoKx1yFDaaKpRrtpDoDAJXsDfcqkvcKGp6Qy0+LQgoEPAF9B38nRkIpP0fdP"
        "APwEAHfAdWaegp1VSLhZahgRQV1tvGHvojKWfWiDM+O+GQS8axjRddCeXesq7DxGNgfp78SQ+tKaDMh6DQ+QMm4ZD2hdI/kXgM3M"
        "qpWuohUSxml7M/XKU65z1MyUJqvYOtgLsLy6eOMI4Bk5nlwg0qBseMvtAqwYWrOyd8w85EPmn2JRvn3VFYUB4Aq1O7u7vyvSA117"
        "cZcsVwz0sUL8GNvJuqjvWz5xpLTEi91nhdkkb0x0QQaJdpzibz5imZRdc4scw3YP5OCm8I9BM2tfkrV0+YqQLk+qNKThmY2EgYd1"
        "qEGXm2xaNOsrWVYtpbn59tffXGX/pReE/wD2xcJi"
    ),
    (148, 28): (
        "eNrtW0tu4zgU3OcUfQLdQYQAG7AALqJbaOsLWN/YhhKtJG/kw+Ukoyr+RElOOzPdk+7AQFCw+BPJVyw+Pio/guDHN/p7745B/N4V"
        "sXjvylDeBV0sv9MUPP2ddsvECH08QrEbjZKlALlm3JOMxqw41HAQNyADXMTDuF9m0xfAAYbtxGjOapfCILv3Lk8BeKx240qtpCLA"
        "pOopEKg1mjsXz2Mjz+PjC1qawRGQy+Bh5K8T3NG0Z7F57wYsuG4zWrWkkcPRZgPse4UdLyjSbKSr96yNm8kRaliYj6/gypqtz8ho"
        "A/kw9Net5hIKPGxirGuYPB6hUkI7/uqjDcw5wiX2653kjQV8E1rUaAPxMPXXyncM5ZajwcvE/BqwEOvJQsRqvmFfqkAdUc1DPMI9"
        "Q1pB3ysCpI/1/KUKLrbv3ZscoXyG1/U8mqiDHJfclwEHC+WKOmew5ymkyI++2UsYLKCV4TfS7r/U0BW26gELusRGS+gAFex+hslb"
        "LMhBrVSsWYhwppbrCMdwNO8JuWs2/o6GxiyB4TyTTCCwID8JZRqYRiGod8NemmoQzmxjIfTBz1jv/W8B+vDYGHCII5QWBhzILyAY"
        "f5U8n0EwCHzUaUKLSBGFHxBMHQ93Xw+BZ5SZAW4CLRN9mgIApcn/0jxrdBQg+Umm8L53EPlfBkOS4ldyPwyEjdCHd7qYCqQPLgPl"
        "eMj41b1fgwrvOG1xbk1HjnZ4b7vFhvgcaKCKnj+USAc59LTCElhVUdjnN4/oDuDEDjI2sRW5uQtyHA0uofwkBfL9CEUqf2nv8yB9"
        "4g54xg7YIL3G5H4eVHMO0NQR/a6xOD8FDRS9pnu8cSAtmLQcPM95xmLh0BQ5YSc/wzCqBjIuqNH4abWQ05YzyOsZQTTXVAMOtvQM"
        "eGrfxji1jx5hscX5neodsym4DKHR8S6+j+czKDCYHu016EuL7k76DOBQz2h+Mja88tUf28mvVkecEm+acrxj1jxfmdm0U2jKcZ4/"
        "MIqxzBlF2v1nbX4CDCSS9Ij0L+nYAF6l8UmxTqHzAYNqjLGJFWDcTa7DCzYKBxla0YBqXKIYxAL2Yy5PiBY44kwiQzJMAB6T0Ygf"
        "VPhF6MONFvyS8QNl+rFai0Z7CAJbacQInXpMsH6EznhJEGGAMWgR5rpqZ1RjGsu5pq4oUu25YFAEjy0Lg/QVdD3fmoPrx4xm7yu4"
        "LF2EEDWWjmsgi8eWL5whULNKRjjYcfBIXaHjun+JdtIz4fW5Ytwbuadkr9M0JBZM2pttPsMUM2KTqaj4Zjr3lbJHpC1DG9FabKX2"
        "DVquGl5qWlSqB4YvMyLdJBzpuMZTErhkXGF26BoNBh3vVnb8HmmFtGADzexEgXYJJdJmi2nYp6gGhlso9gbIcEKBIRfJfrqwB0zX"
        "AHkoMHtXzGOxEVpPewjZFRviywbOMea7pwhu4qmq9Ayi+cLDcoXTIUjVVYSeIqm0aJrGmCuFTDW6pYRvEdCBrANqsPTAw51lOLd4"
        "iiDTChW9kfqRnrlSftR92dK1H39d7c7UqF/7qSAr2Jg0bidan01ax4lQ5RKd2208HZ+W2+sZ4nQOmN0ipisl9FypOBOtQI8k4bnC"
        "26dLZUtrVWdpnwKX/VKfS0UkqcFxuPD5t0pRQCNvRBNAeamhRYv1iiofJqpsWF5aYG8KQGkbqPFICS+sWlBanOZw7CVnAfNRTiTc"
        "yFeJaSwTxIcSYTx1OnvwVysR6U01kyYOXAr+ClfSomka93v3qNKiWVqkQfkPYDQZSLhsYxupiDRxufZKCHIZGU4c1D4TmpWJwi3S"
        "Gp4k0PxA0Qeth2gLexlfYQjXOuSNTRcJ/XLxYmwHKexEeO1VqHtITMuqCCa72mNYnPbE29CcNHe0keWxMi03ghRpoP853a3wWOh7"
        "ObKXDKNTklnOzvhHYAOvO0PWi/xZiAwBKKPrPEk5ourtQCxe0qfGy3Z3hs6BcWujQd1e7R2QY8xTbieBzsDFLnXO2FrGxdZg3T7Z"
        "T1cJC9NpqP0MJRP+krqZdvbTzuwLvDZ1kNzy9LeFZ+t5HbmNyVHk+ii0abHeYHKQ/BVp18iINT30Bhrqmm+23LK9IRwxopM0DpbL"
        "uMIxmaWRZ7mfxjkdkmWjFzY6m4iVwpV1I5nhanDW+t1em7ZOzdZfqz1caBqTFkoAkdula06IYU5hfYKKuklfgx7uWujy6XZMdUD0"
        "p7bOvBPl3Orx1OFYMpzkvqpyXhFSn9I+oOVKrVf2HXOBJZ3vsLh3npProFczv8yo/Uet73KRlim+Lhs4rqSx3HnvMY2+QQc5rZ03"
        "AXDHQJfWchsHm3m4IpF5Lu3A5hZsdl6MIzJ992bFDz6tdHLYy/tHvjZN7arXzcI0yl4bheYhaWl9Gk9JrE/LSglwqj3XTux8iU2n"
        "RehhkFKZ5RpZx/v2CxbGy3+5tNCX+QVUuojxhnjpuWiXWqyfF5l7ZXf8fePANCX4YpFxlcsa5L/K8GdFdWNlKan3+hNc/DztgF+9"
        "FYSWsUu4E47DDIMUKvwFfZWxpiqJfAy9mB+vTwY6Gyj8Blme+N/wnFtAY4d1xWCcYJ3Rl86fjUEuNW3w92wHnd+eK8wXHdJly9e1"
        "GtbcMx+Acz+wk2KlQ+RGarq2dkCj3Bb3XRI9feaGi+EP50Ar8J3lzMbtnB8xYyOX2Mwb6W2GY4oDl+Fo1ac3arCpq0gXvLyoDqV+"
        "mlj05W0njATYSAq/xODpKBeGZeQvwxCEjC6yAmHBpFU26FFv4XOCqxVAn1FNsICvPKZSx6enpEt1r2Yb7pxWnN10jbXpInagWbuS"
        "QRm0W/7sHc4XOIil3ua2vRnQA2DIwdHn5f+8GNYfXeR4cR6kxlm2kKNvzF3PEIsMnbtWI7XV0kVTtbzx8p+0TAFwkT2G/NSxZqOj"
        "X/3ehMCqPSgGouYJQH4IKKJq7GPtLXaAXvUAESy8o1Pxrch0Q7jupreG4KcF3HEC/euOObjZss6Q+tcst7n1DhYufsUV+tPf823C"
        "KTC31bkN7PCG78KgGmcDWz/PYXJ6tGLg980+tvbXMWFwPNEHkbN/4hnsIVDdOjKiKFVnOrpBvF+ErA7RRkejSvH4TOVXfOwt56Cs"
        "KwJ9o8MbAnJARUY8IYaNARCSw+T84Z32Tys0cAfuV58uPCQdRKIf7ecruDAU+rKMHWGXShUy/Xg0Dzrct9Wdglgv+dk1m7qZiM19"
        "nlMFdU/nfX3I64B+5rCp2CfCPTiLEUr1xQNPzgiVCXNcK/E4cGfCI72EaypsoEHoCJPHDHP9yC3nSNeLV5cUj9DsgfMRIeMP/GD9"
        "TyPHMdjq6aXRlRbg4uAoTDT1svF4QWejlmLSCP+fpLfhTedku8fzjruHeXy13nfj04mBzjdbrRU7/SHB9HRmtxC3pfF+vrNXP+xu"
        "MYn72pMjco8czIMcdynHUdrbHfHRhygly9GpNV+T6xZa7DeDO0wBZoeak7X4cWduZPSjmD6SRo1/ROHlfGb/34WEamTg7WQ1Yy38"
        "n7UPR6L+mYnk+fM+if9j/Yx5JGAKi8LKqcAVpIu6v9roZBWm+qJI3yXhuBjTjefF085QAjuWykWNTt1D4VgZmgvZWWRfRef9Dtn/"
        "tri7/w8q/BeiKNvHZpMu8EVKL008utiEOo0EeLWRPn431NqA9hGPRzGz7vILkg6NNjaNFzqvkfBvhR/njN9tdAYL+b8svLUtaG9h"
        "v3PEdcQssquNLqYcGPjVD9IO9mu4mrcY8FOZppqKpHZe+KKL+tJ5eXH6MPr//R9tLtwnDFDnaSb13xKh/Xoq1B+1DqG05SKvrm7v"
        "G/z3wz8yWP4m"
    ),
    (148, 35): (
        "eNrtXFuOozgU/e9VzAqyBywkIgXJH51d8MsGCJBUEiXhC/ghi+uVDOf4hXmkUj09XdM1kUpX+IFj+x5f3xf112r11xf6+1EfV/GP"
        "uohFTwL5FKlj+ZW24Nsfy7pG9mSX9CSXC4w9ieBH/Ras3iPHoO98ezH2s1m6I0s3/Sk7i03Pm01frPDEup0c9n0DOYHLu++GlOD3"
        "HNmTrF4M/jTWkl1NrATojzpLeq6Wm6TnCp5aMPm4EbrLbnAUdVWm+Pu9l8Lf+25vYjUhRwEZLVcvJn/ebcqjG/2oO5A6Ejh6PWvz"
        "oH/qyF/UtUHfeomkew98BXNz2ZMMTy0YfgFL53h9RkP1hQ70H3iaS9lzqJY9K9+ilWZ5KcKedbauQV0bSu+982rhAC+SSvZv1OLF"
        "6k9jeImT3cUUsP1VmqcS/MelKslwXwrw2E9PbqP0bLSGIChmKN55msHk9sXkz+Uz+JSDz2W65UXcs2gNIjwWSzFz/fZIOAUhTiow"
        "MaN7V0DMl5HafyiLb9Cf8vg7zjPVKZxs3Lh3sl0d1BWs4gVpzBN8gcnULtlXL0b/Bxh9gBwuQA5gL0kJlr99xy0MGJzBwC4OtIZW"
        "41jzqQQ5gjy2ob8Yo6GF9qvKYG4OycoS+UFSwEGhBt3KDxBcsOq12HtyhHVz5OOT/BkC6xtwOUBMHKzAaIG3DjdGC4B1gFABCJGM"
        "ileoAS00iCJ+JEnu+KHfs6x3F13I1Tw/xuyxW+KKH4PAVupf+8mZzsJRAORHabwrv4acMHSF+b5tV8+TM96oIqmNhRHZR8GwWMFm"
        "PAVi6Bv6l0mBH7qvcdGtk146bvjj635qgDZJDSv1DH3ngKktyskCelEDzN/xNCtFsYm/Y1lPkCvmchXRPGcWCddxldsP4uC2/bUr"
        "P8p1D/JOGltTuSDAvV9DSqyQ+vETi8u3KYjUptI+7jc1hxPkCVLTVorhAI1ivQ4SFh/XDYrx5kHdScRQ/XpU1wA56yp1vxh/TKtA"
        "/pwvfZG0iJ5c5MN1xItrEz+ztsVtoo5zBT+eZQX51qS8rz6Ab6KkTYmc5BdAj0soAeqbpF4KiHNfH8nEHXysO7lASvpihUe0w/3d"
        "lbKLIxeoLbkIJpKhwfbtBAn98ZEm5GzOzWWXFBzbgtuSdYEpbuFs4hvS1BUsxpF28rOuZqsYDdXX3eiCXJvXCshs9Qb6nWL2g2Hz"
        "YZw3VpWpBHcN1i9utY7xQrvowTpibx3UikZ1fGrCSL/h6tTaXJ3dg9E28arcKQ8sdsgyIKdrNpzK9jPeqFI54eo7EEhS4EX48Eke"
        "AK5OHoH1wrtHGsNLOw0vtGPwdoGfKqjMqCeS/vcOeJoj49MwmA1ewxILKltj0i/sgKeDVW0yekUkGsigwHi0aAofsN0kTRDpg6AE"
        "vtJbUj1KY0e5oK5OvfPj9vyEouOIe+0M4vqxjvrXznZRRb4W4QYC8g/Qy/mUv49ydulwTO7KDlxjAGEGiLf619yc3Tqu/jr4NDdn"
        "V3faprpuZ+s0MXU3O/wOK+ooyIU5Em7vSQq0kjO8RMktvlsprhrW7vE0x33u/UHNwOBlBKQhzOSQdGLjo9MQAvgiFag9zwIQLueP"
        "Ro66XBpCrZQy210LPA7lzExUF6wi8wnrCuwodROS0mKdpMOm53T3gtTY6pzbanf5HhtRf4iMgtvAM3SA/FPcCFN9TjRzpBbruS2S"
        "3EU8LOq6cFhs3UELhW5tobm8rSmGoZmDHEU8QTinphbDuQTmomoxShcywGCG6jDoPTT9LuqN1MwllLrhEJm6eywmdS1XpOq25idD"
        "18+SWNrhhdGkQ8wU20RPjNqrONKXF9dxYGxFbIcsK6yy2fGJnE59xlMj2SYTqBQKTVITinBizUGPpJ4xvxqN6xmXmfZDEfk7PDW8"
        "KtTPLkhokoxvCHP2lDGmYJ/o2HFpIZ7JqaweaSka7KmHc+orUM+KNNIRjXNMaRJrjaS1OqS7KVmn8RvqOuow7HcLzN1aKYR66tCF"
        "CLDjNRaD/LVmTYgbIJ5RPEFnzuNQR9d2vNh5yOJAR1F4KJQsJFzQerLOFU7jMkJ3YI5vZ+fSYeLXwCgo+lzHusvNqgzsxxk4NaIL"
        "bd3gXSsxMDXXwPPP8GGRMpqEUK+cIpkgLix+R1x1nXMLqdKJREIFoCGQsocKMkFIqc1RLolBLMnbY1+wjmzPqtZWl+bp2isytXYz"
        "q6Bz2jsL7n0C0AojsPe8z7Erewvzxl6LezyNGloCHggvt4YUKO4BeEfq7bSu8OtY5N04qUM/6epsFyjUFZQOAq8CBOlP3vvOEqUe"
        "AzyuobT9WjRcrTZS0SiGF4Vy2eH6sqaRHdiJB3oah0GdmXOTel34xH0pxhux0NAwBKr2NNRPe9RdrWOArNgpBkzh61qVmIYaTXaX"
        "TvwmRgSO8EIM7RWuEq19K9D4ll4mzABtIp8KbGi/CeO9VeJdEItCOpOe3u/0kFE/Tu6uMn9w3ra8YczpbnxsU0VzNnSmBHc6Ma4b"
        "v45D3We2e44FdOS0fkOplEQ5cVTWVMYdmCXADGRlkGaZ0vXNhU0IZzb1rGS0jLFRphpSn0JnFisQgtkNTzC/gRVXf373VGpNe7Do"
        "bTqpq9IFJ1U5I0+546rBRy9HVsqD31DzJ61WoXfScN9hMfPRu1eSWuhWAnxRNDvV+gQkNsBkuRBr+rYcByOgGQfLxVSTzp1yPgNy"
        "5qQV0mgdha+sNIlBNe+Ooe4vNbRJWlr5qVHFHWmVqiYnDSeZznce1eXo16XThuPMALS2OIrDWac8f3QTGItp4LZmqMbWVXGgdY2K"
        "Pg8QBoKvoalTCky8nsD42VU+WHn61CoX9/TGmBrEbJEYzlAZZfbhXvnnDG6dIeZ0g/uGDqY5QzAZOiLuHEpshqRZJe9lt3x7Kqbb"
        "72xusZz55mIjDKp5AOc0DXa580aYWUhuDddRw9wbRP9dzjQov/J0+Ja77c+ZImBUlwuv7ojFnBIvI/jsq7NEMM0iAvWusBzb/G4x"
        "dGB3gmq+Kd5gjo1wS1XlYpdAzt9s8YwJjewgzmpkvneW/SOJ0sLxNO6MTexm9v5xQz6zz5RpfGM0yc5KPKbdFmLB26AkHu02AO7t"
        "V2VIGGNwlQz163wl59ehQWMOJo/ZyOg8JJuJ5GaDQqzYLIA/mUK5mdli/vgcvPPRTTBTxyAaG9pNbGMJiLaA1JHBmvbKWWI9LjkD"
        "FLT+XJ31wO2VRy/Wno87vbw2XtHhJzl7F1c8qcVMocfdHdXVVogNsSt1GHQOiUo8jkDNy3FmeHW3J1N/wsFacJ3PbreEXBA+HoZu"
        "YvUETv9pSg8+IvBMQ5I9psLZOnWYhDKhkAsNezFtyNR4Rmt3dWTl4lCd8oF4DQWGd6PwiTMdjXxnXRQbp0dgAgWMYRwgSct0DYMC"
        "RHioXSTssoM43fFdWPgHSVeCCVroIL/xrjCqn9mpnTdC3yFuppx4Rf1ytDmJ0NJ6spPTDeNOzjXs7BtzQ5Uy0T8+amh8MAzISnxa"
        "vpnWeolWTaRfnGuQS51HDYtDLQ4vn+snTcxKBVFsSGzPsDFtUrnSIRHaIjRD9rTlt3D/yocEhjqtFzqbOkYvqA4PZhDp0OMAnqF4"
        "cocek8eviQ/v6bv93v5XyY/4GoxmzMrY4BFt8EinHijLUX83SO+Ni+RXtA/8Ip+OW6kzWo5bE69yZnNnfQ+dNTBqabLg1zr0mgHG"
        "9I/qD2Jeua//wtegwiQknmz6wRGnN+OHCK6jEiDWv0MGn31vyGmG/c4PdPVhcvGLNhdW5x6drSw5Kq2PptuL/f/wu1+VhQkFZUxs"
        "1tdpsPPKCTEepFFeVFrKCFIm9Kda/wBjv/TFiq2FQmpi7JtUexlUZxTPItEerk6lOVhx4BJ1GMzRsxLaNaJWFC+v6AWMJz49pDs2"
        "HIbadKKPgcE5GqGChpWycb04vBjmUzG3dVS8WpPlao2hy4zxN/AOqADpZlgciIoDoEFTeygvaGmIYZGLYYqT1+UFjqfA4cVwKYmz"
        "SOhIU8YsQRsKvTD9Ugw/Q1YXh2UrnVK1TCbegtsAHMkQHM5ZR9Q4ENErUyVikgV1kf4Xl7eV0F5XrZ26JUT6qR3cfiOp9wLH8res"
        "R4CjxNlj0Cbj0wyhfVAODDv9fsXPVMnlwDjlRgndziFKN0pl5YUuSutc9AQOUUM0KI9vsNFwGqQROYNvuI6FJTDjgMH3cvWSHM+i"
        "pFAfU8kJmfr0DRqQJuRCKVeVRMRvqxKdldaoVA74HoLEeHEC868QOuoeKBZ8IzbvMprIoU7SS3K6BNOv4jVAF+df/PdA8Ed/dac0"
        "S+Z/4bQVyIHhZ/DMi2ORpELd1cYkmK5b2UjbEZw8ihF3EYTwP5Ri3lntIhsMLIdDvfP1qeVvYDp1A53G7XgRgl2Rxy4ksDBY6pju"
        "Es7nmM5YFXFB1Lh+VSiGqY2XUPoZeC+m/6bva6XW0pllxH+RkNtsPJLRlzNk+tWvq0QwhA4JvyobDhWakByzP3GB62CafDH98zTH"
        "PWKZ2iMba8LU3ANzJ4CMLhZDTvL/FNXqu2zm8YbWaRs7D+8X+Jz6b0AX51A="
    ),
}
_faravahar_cache = {}


def _faravahar_rows(key: tuple) -> list:
    """Cell rows (3 chars per cell) for one stored size (decoded once)."""
    if key not in _faravahar_cache:
        import zlib
        raw = zlib.decompress(base64.b64decode(_FARAVAHAR_DATA[key])).decode("utf-8")
        _faravahar_cache[key] = raw.split("\n")
    return _faravahar_cache[key]


def _render_faravahar(key: tuple) -> list:
    """Printable ANSI lines for one stored size. Colour codes are only emitted when
    the colours change from one cell to the next."""
    ckey = ("ansi",) + key
    if ckey in _faravahar_cache:
        return _faravahar_cache[ckey]
    pal = _FARAVAHAR_PALETTE
    lines = []
    for row in _faravahar_rows(key):
        line, state = "", None          # state = (fg, bg) currently set on screen
        for i in range(0, len(row), 3):
            glyph, fg, bg = row[i], row[i + 1], row[i + 2]
            if glyph == " ":
                if state is not None:
                    line += "\x1b[0m"
                    state = None
                line += " "
                continue
            if state != (fg, bg):
                r, g, b = pal.get(fg, (0, 0, 0))
                seq = f"\x1b[0;38;2;{r};{g};{b}"
                if bg == ".":
                    seq += "m"
                else:
                    br, bgc, bb = pal.get(bg, (0, 0, 0))
                    seq += f";48;2;{br};{bgc};{bb}m"
                line += seq
                state = (fg, bg)
            line += glyph
        line += "\x1b[0m"
        lines.append(line)
    _faravahar_cache[ckey] = lines
    return lines


def _pick_faravahar(width: int, max_rows):
    """Stored size (cols, rows) to draw, or None for the text banner.
    'fit': the largest area within width x max_rows.  'big': the widest that fits
    the width (max_rows ignored).  None if nothing fits."""
    if FARAVAHAR_MODE not in ("fit", "big"):
        return None
    fits = [k for k in _FARAVAHAR_DATA
            if k[0] <= width and (FARAVAHAR_MODE == "big" or max_rows is None or k[1] <= max_rows)]
    if not fits:
        return None
    if FARAVAHAR_MODE == "big":
        return max(fits, key=lambda k: (k[0], k[1]))
    return max(fits, key=lambda k: (k[0] * k[1], k[0]))


def _banner_rows_planned(width: int, max_rows) -> int:
    key = _pick_faravahar(width, max_rows)
    return key[1] if key else 5


def print_banner(max_rows=None) -> int:
    """Print the Faravahar at the top of the screen, centered in the terminal, and
    return how many rows it used. Falls back to the RAMIN VPN text banner when
    nothing fits (or FARAVAHAR_MODE is "off"). The 'RAMIN VPN' signature still
    appears under the connection box (print_ramin_signature_line).
    max_rows = rows available for the banner; by default it is worked out from the
    terminal height and the measured height of the rest of the screen."""
    key = None
    try:
        size = shutil.get_terminal_size(fallback=(80, 24))
        if max_rows is None:
            max_rows = _plan_layout(size)[1]
        key = _pick_faravahar(size.columns, max_rows)
    except Exception:
        key = None
    if key is None:
        _print_text_banner()
        return 5
    pad = " " * ((term_width() - key[0]) // 2)
    for line in _render_faravahar(key):
        print(pad + line)
    return key[1]


def _cell_width(ch: str) -> int:
    """Terminal cell width of one character (0 for combining marks / joiners)."""
    import unicodedata
    o = ord(ch)
    if o == 0x200D or 0xFE00 <= o <= 0xFE0F or unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


class _RowCounter:
    """Transparent stdout wrapper that counts how many terminal rows get printed
    (newlines + soft wraps of long lines). Used to measure the height of the
    connection screen so the banner can be sized to leave room for it."""
    _ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

    def __init__(self, real, columns: int):
        self._real = real
        self._cols = max(1, columns)
        self._newlines = 0
        self._wraps = 0
        self._col = 0

    def write(self, s):
        for ch in self._ANSI.sub("", s):
            if ch == "\n":
                self._newlines += 1
                self._col = 0
            elif ch == "\r":
                self._col = 0
            else:
                w = _cell_width(ch)
                if self._col + w > self._cols:
                    self._wraps += 1
                    self._col = 0
                self._col += w
        return self._real.write(s)

    @property
    def rows(self) -> int:
        return self._newlines + self._wraps + (1 if self._col > 0 else 0)

    def __getattr__(self, name):
        return getattr(self._real, name)


# ---- Connection info (active server + ping + public IP) --------------------

def get_current_selection():
    """Asks sing-box (via its local Clash API) which server 'auto' picked."""
    try:
        url = f"http://127.0.0.1:{CLASH_API_PORT}/proxies/auto"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        return data.get("now")
    except Exception:
        return None


def get_proxy_delay(tag: str):
    """Latest measured latency (ms) for a given outbound tag, per sing-box."""
    try:
        url = f"http://127.0.0.1:{CLASH_API_PORT}/proxies/{urllib.parse.quote(tag, safe='')}"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        history = data.get("history") or []
        if history:
            return history[-1].get("delay")
    except Exception:
        pass
    return None


def get_traffic_totals():
    """Cumulative download/upload bytes since sing-box started, per its API."""
    try:
        url = f"http://127.0.0.1:{CLASH_API_PORT}/connections"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        return data.get("downloadTotal"), data.get("uploadTotal")
    except Exception:
        return None, None


def format_bytes(n):
    if n is None:
        return "?"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def probe_proxy_connectivity(tag: str, timeout_ms: int = VERIFY_TIMEOUT_MS):
    """Real end-to-end health check through the selected local mixed proxy.

    Do not use Clash API /delay here: the same actual proxy path used by the
    user is what decides whether a server is healthy. This also works across
    VLESS/Trojan/VMess/SS/Hysteria2/TUIC/WireGuard and other parsed outbounds
    as long as sing-box can establish the tunnel.
    """
    if not tag:
        return False, None, "no selected outbound"
    proxy_url = f"http://127.0.0.1:{LOCAL_SOCKS_HTTP_PORT}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    )
    urls = [
        URLTEST_URL,
        "https://cp.cloudflare.com/generate_204",
        "https://www.google.com/generate_204",
    ]
    last_error = "proxy test failed"
    for test_url in urls:
        try:
            started = time.monotonic()
            req = urllib.request.Request(
                test_url,
                headers={"User-Agent": "RaminVPN-Health/1.0", "Cache-Control": "no-cache"},
            )
            with opener.open(req, timeout=(timeout_ms / 1000.0) + 2) as resp:
                _ = resp.status
            return True, (time.monotonic() - started) * 1000.0, None
        except Exception as e:
            last_error = str(e)
    return False, None, last_error


def fetch_public_ip_info():
    """Queries an IP-info service THROUGH the local proxy, so it reports the
    exit IP/location that others on the internet actually see."""
    proxy_url = f"http://127.0.0.1:{LOCAL_SOCKS_HTTP_PORT}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    )
    try:
        with opener.open("http://ip-api.com/json?fields=status,query,country,countryCode,city,isp,org", timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}



def get_subscription_url_for_tag(tag: str):
    """Returns the subscription URL that produced this outbound tag.

    fetch_all_outbounds() prefixes every server tag with S{sub_i}-, for
    example S1-01. Example or S3-12. Example. We use that prefix here to
    show the matching subscription link in the connection details.
    """
    if not tag or not tag.startswith("S"):
        return None

    prefix = tag.split("-", 1)[0]  # e.g. S1
    try:
        sub_i = int(prefix[1:])
    except ValueError:
        return None

    if 1 <= sub_i <= len(SUB_URLS):
        return SUB_URLS[sub_i - 1]
    return None


# ---------------------------------------------------------------------------
# A little celebration, played once a connection is confirmed working.
# Kept to a SINGLE terminal line (only "\r" carriage-return redraws, never
# a multi-line cursor-up move) - a multi-row version wraps unpredictably on
# narrow mobile terminals and leaves a trail of garbled color blocks
# instead of animating in place. One line is safe on any width.
# ---------------------------------------------------------------------------
def print_command_help(top_outbounds_count: int, fragment_supported: bool, fragment_preset: int = None):
    """Prints a small three-column reference panel of every live command the
    person can type + Enter: Fragment/server commands on the left, DNS
    provider commands in the middle, and subscription-switch commands on
    the right, so all three fit side by side on a phone without the panel
    getting too tall. Descriptions in green, keys in red - re-printed
    fresh (via render_connection_status) right after every connection box,
    below the ports line - initial connect, rescans, server switches, and
    Fragment/DNS/Sub changes - instead of only once at the very start."""
    # Switch Server / Switch Sub are NOT listed here any more: they live under
    # "Fast Connect", right above the prompt (see print_switch_lines).
    left_rows = [("Fast Connect", "FC"),
                 ("Auto Setting", "AS"),
                 ("Free Vless", "FV"),
                 ("Show Protocol", "PC"),
                 ("Search Web", "SW"),
                 ("AI Engine", "AI"),
                 ("Reload", "R"),
                 ("Speed Boost 1", "B1"),
                 ("Speed Boost 2", "B2")]
    if fragment_supported:
        # One combined row instead of five: F1..F4 select a preset, F turns it
        # off. The keys themselves are unchanged - only the help line is merged.
        frag_letters = "-".join(p["short"] for p in FRAGMENT_PRESETS.values())
        left_rows.append((f"Frag {frag_letters}", f"F-F{max(FRAGMENT_PRESETS)}"))
    else:
        left_rows.append(("Fragment", "N/A"))
    left_rows.append(("SubLink", "SL"))
    left_rows.append(("Delete Link", "DL"))

    mid_rows = [("Test All", "AT"), ("UDP/TCP", "ATU-ATT")]
    mid_rows += [(name, f"D{i + 1}") for i, (name, _ip) in enumerate(DNS_PROVIDERS)]
    mid_rows.append(("DNS Off", "D"))

    right_rows = [(SUB_NAMES[i], f"L{i - BUILTIN_SUB_COUNT + 1}") for i in range(BUILTIN_SUB_COUNT, len(SUB_NAMES))]

    # Add the requested three section headers above the command rows.
    # Keep them compact so they remain usable on a phone-width Termux screen.
    left_desc_w = max(len(d) for d, _ in left_rows)
    left_key_w = max(len(k) for _, k in left_rows)
    mid_desc_w = max(len(d) for d, _ in mid_rows)
    mid_key_w = max(len(k) for _, k in mid_rows)
    right_desc_w = max((len(d) for d, _ in right_rows), default=0)
    right_key_w = max((len(k) for _, k in right_rows), default=0)

    active_sub = None if _state.get("free_vless_mode") else _state.get("current_sub_index")
    active_dns = None if DNS_DISABLED or not DNS_WINNER else DNS_WINNER.get("name")

    def cell(desc, key, desc_w, key_w, active=False):
        if active and desc == "AI Engine":
            # AI Engine: light blue + bold while the connected server is its pick.
            return f"{_C.BLUE}{_C.BOLD}{desc:<{desc_w}} : {key:<{key_w}}{_C.RESET}"
        if active:
            # Active entries are green and bold so they stand out clearly.
            return f"{_C.GREEN}{_C.BOLD}{desc:<{desc_w}} : {key:<{key_w}}{_C.RESET}"
        # Inactive entries are shown in a single crimson color instead.
        return f"{_C.CRIMSON}{desc:<{desc_w}} : {key:<{key_w}}{_C.RESET}"

    def left_active(desc, key):
        if desc == "Free Vless":
            return _state.get("free_vless_mode", False)
        if desc == "Speed Boost 1":
            return SPEED_BOOST_ENABLED
        if desc == "Speed Boost 2":
            return SPEED_BOOST2_ENABLED
        if desc == "Fast Connect":
            return FAST_CONNECT_ENABLED
        if desc == "Auto Setting":
            return AUTO_SETTING_ENABLED
        if desc == "Search Web":
            return bool(_state.get("sw_pending"))  # SW pressed: its prompt is open
        if desc == "AI Engine":
            # active while the server currently connected is the one AI picked
            return bool(_state.get("ai_tag")) and _state.get("ai_tag") == _state.get("render_tag")
        if desc.startswith("Frag "):
            # Combined Fragment row: highlighted while any preset is active.
            return bool(fragment_preset)
        return False

    left_blank = " " * (left_desc_w + 2 + left_key_w)
    mid_blank = " " * (mid_desc_w + 2 + mid_key_w)
    n_rows = max(len(left_rows), len(mid_rows), len(right_rows))

    total_width = (2 + left_desc_w + 2 + left_key_w + 3 + mid_desc_w + 2 + mid_key_w
                   + 3 + right_desc_w + 2 + right_key_w)
    bar = f"{_C.MAGENTA}{'-' * total_width}{_C.RESET}"
    print(bar)
    print(f"{_C.BOLD}Commands (type + Enter){_C.RESET}")
    # Section headers: gear icon in yellow, header text in blue+bold.
    header_left = f"{_C.YELLOW}⚙{_C.RESET} {_C.BLUE}{_C.BOLD}Setting{_C.RESET}"
    header_mid = f"{_C.BLUE}{_C.BOLD}DNS Settings{_C.RESET} {_C.YELLOW}⚡{_C.RESET}"
    header_right = f"{_C.BLUE}{_C.BOLD}Sub Links{_C.RESET} {_C.CYAN}🔗{_C.RESET}"
    left_col_w = left_desc_w + 2 + left_key_w
    mid_col_w = mid_desc_w + 2 + mid_key_w
    print(f"  {_pad_visible_wide(header_left, left_col_w)}   "
          f"{_pad_visible_wide(header_mid, mid_col_w)}   {header_right}")
    for i in range(n_rows):
        left = cell(*left_rows[i], left_desc_w, left_key_w, active=left_active(*left_rows[i])) if i < len(left_rows) else left_blank
        mid = cell(*mid_rows[i], mid_desc_w, mid_key_w, active=(i < len(mid_rows) and mid_rows[i][0] == active_dns)) if i < len(mid_rows) else mid_blank
        right_active = False
        if i < len(right_rows) and active_sub is not None:
            # right_rows is kept in the same order as SUB_URLS: S1..S8, then L1...
            # Comparing the actual subscription index avoids partial highlighting.
            right_active = (i == active_sub)
        right = cell(*right_rows[i], right_desc_w, right_key_w, active=right_active) if i < len(right_rows) else ""
        print(f"  {left}   {mid}   {right}")
    print(bar)
    _gap()


def _math_bold(text: str) -> str:
    """Sans-serif bold letters/digits (the same style as the CONNECT title)."""
    out = []
    for ch in text:
        if "A" <= ch <= "Z":
            out.append(chr(0x1D5D4 + ord(ch) - 65))
        elif "a" <= ch <= "z":
            out.append(chr(0x1D5EE + ord(ch) - 97))
        elif "0" <= ch <= "9":
            out.append(chr(0x1D7EC + ord(ch) - 48))
        else:
            out.append(ch)
    return "".join(out)


def connect_source_label(tag) -> str:
    """Which source a connected server came from, WITH its name: T<n>_<Name>
    (Free Vless source), S<n>_<Name> (built-in subscription) or L<n>_<Name>
    (the user's own link) - e.g. "T29_Telegram@vpnjey". '' if unknown."""
    t = str(tag or "")
    m = re.match(r"^FV-([A-Za-z]+\d+)-", t)
    if m and m.group(1) in FREE_VLESS_SOURCE_CODES:
        n = FREE_VLESS_SOURCE_CODES.index(m.group(1)) + 1
        name = FREE_VLESS_SOURCE_NAMES[n - 1] if n - 1 < len(FREE_VLESS_SOURCE_NAMES) else ""
        return f"T{n}_{name.replace(' ', '_')}" if name else f"T{n}"
    m = re.match(r"^S(\d+)-", t)
    if m:
        n = int(m.group(1))
        name = SUB_NAMES[n - 1] if 0 <= n - 1 < len(SUB_NAMES) else ""
        if 1 <= n <= BUILTIN_SUB_COUNT:
            return f"S{n}_{name.replace(' ', '_')}" if name else f"S{n}"
        if BUILTIN_SUB_COUNT < n <= len(SUB_URLS):
            ln = n - BUILTIN_SUB_COUNT
            return f"L{ln}_{name.replace(' ', '_')}" if name else f"L{ln}"
    return _px_feed_label(t)


_SITE_TAG_RE = re.compile(r"^PX-Site_((?:[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*\.)+[A-Za-z]{2,24})(?::\d{1,5})?-")
_TG_TAG_RE = re.compile(r"^PX-TG_@([A-Za-z0-9_]+)-")


def web_source_label(tag) -> str:
    """Servers found by SW: 'freeproxydb.com' for a website search, 'Telegram : NAME' for a
    Telegram channel search. '' for every other source."""
    t = str(tag or "")
    m = _SITE_TAG_RE.match(t)
    if m:
        return m.group(1)
    m = _TG_TAG_RE.match(t)
    if m:
        return f"Telegram : {m.group(1)}"
    return ""


def _px_feed_label(tag) -> str:
    """Name of the dedicated protocol feed a PX-... server came from ('' if unknown)."""
    t = str(tag or "")
    if not t.startswith("PX-"):
        return ""
    names = ["FreeProxyDB", "Cloudflare WARP Live"]
    for feeds in PROTOCOL_EXTRA_SOURCE_URLS.values():
        names.extend(label for _url, label in feeds)
    for name in sorted(set(names), key=len, reverse=True):
        if t.startswith(f"PX-{name.replace(' ', '_')}-"):
            return name
    return ""


def switch_sub_range() -> str:
    """What the Switch Sub line shows: every switchable group at once -
    built-in subs (S1-Sn), Free Vless / protocol-search sources (T1-Tn), and
    the user's own added links (L1-Ln, only once at least one exists) -
    joined together. All three are typeable at any time regardless of the
    connection's current mode (SUB_COMMANDS / FV_SOURCE_COMMANDS / LINK_COMMANDS
    are matched unconditionally in the main input loop), so the display no
    longer hides two of the three groups depending on which mode is active."""
    parts = [f"T1-T{len(FREE_VLESS_SOURCES)}"]
    custom_count = len(SUB_URLS) - BUILTIN_SUB_COUNT
    if custom_count > 0:
        parts.append("L1" if custom_count == 1 else f"L1-L{custom_count}")
    return "_".join(parts)


COUNTRY_DISPLAY_LIST = [
    ("🇺🇸", "America"), ("🇬🇧", "England"), ("🇩🇪", "Germany"),
    ("🇳🇱", "Netherlands"), ("🇫🇷", "France"), ("🇨🇦", "Canada"),
    ("🇨🇭", "Switzerland"), ("🇸🇪", "Sweden"), ("🇳🇴", "Norway"),
    ("🇫🇮", "Finland"), ("🇩🇰", "Denmark"), ("🇮🇹", "Italy"),
    ("🇪🇸", "Spain"), ("🇦🇹", "Austria"), ("🇧🇪", "Belgium"),
    ("🇵🇱", "Poland"), ("🇷🇴", "Romania"), ("🇹🇷", "Turkey"),
    ("🇯🇵", "Japan"), ("🇸🇬", "Singapore"), ("🇦🇺", "Australia"),
    ("🇮🇳", "India"), ("🇧🇷", "Brazil"), ("🇭🇰", "Hong Kong"),
    ("🇦🇪", "Emirates"),
]


def _three_column_rows(items: list, columns: int = 3) -> list:
    """Arrange items row-by-row across exactly three columns.

    Row-major ordering makes the list much easier to scan on a phone:
    1 2 3 / 4 5 6 / 7 8 9 ... instead of filling one whole column first.
    """
    if not items:
        return []
    rows = (len(items) + columns - 1) // columns
    return [
        [items[r * columns + c] if r * columns + c < len(items) else ""
         for c in range(columns)]
        for r in range(rows)
    ]


def _render_three_columns(items: list, formatter=None) -> None:
    """Render three compact, non-wrapping columns sized to the current terminal.

    The previous implementation used a hard-coded 24-column cell.  On phone-sized
    Termux terminals that forced the third column off-screen and long country names
    wrapped onto the next physical row.  This renderer measures the actual terminal
    width and uses the smallest width needed by the content, so every row stays on
    one physical terminal line.
    """
    formatter = formatter or (lambda x: str(x))
    rendered = []
    for item in items:
        rendered.append(formatter(item))

    rows = _three_column_rows(rendered, 3)
    if not rows:
        return

    # Find each column's required visible width.  There are no ANSI sequences in
    # the protocol names, but country cells include emoji, so use the wide counter.
    col_widths = []
    for col in range(3):
        col_widths.append(max(_visible_width_wide(row[col]) for row in rows))

    available = max(36, term_width() - 2)  # leave a small left/right safety margin
    # Two spaces between columns is the normal layout.  On very narrow Termux
    # screens one space is enough and still keeps the columns clearly separated.
    gap = 2 if sum(col_widths) + 4 <= available else 1

    needed = sum(col_widths) + gap * 2
    if needed > available:
        # Keep all text on a single physical row.  We only have a few fixed,
        # short labels; shrinking empty padding never changes the text itself.
        # If the terminal is exceptionally narrow, allow columns to touch rather
        # than introducing wrapping caused by large padding.
        gap = 0

    for row in rows:
        parts = []
        for col, value in enumerate(row):
            if not value:
                value = ""
            if col < 2:
                parts.append(_pad_visible_wide(value, col_widths[col]))
            else:
                parts.append(value)
        print("  " + (" " * gap).join(parts).rstrip())


def show_country_list():
    print("\n" + _C.BOLD + _C.CYAN + "Available Countries" + _C.RESET)

    def fmt(item):
        flag, name = item
        # Flags are kept visible while the name remains plain white for readability.
        return f"{flag} {name}"

    _render_three_columns(COUNTRY_DISPLAY_LIST, fmt)
    print()


# Human-facing names for the protocols this program can actually parse into
# sing-box outbounds. Scheme variants such as hy2:// and warp:// are grouped
# under their canonical protocol instead of being shown as separate protocols.
# Fifteen entries = five full rows in the three-column "PC" list.
PROTOCOL_DISPLAY_LIST = [
    "VLESS", "VMess", "Trojan",
    "Shadowsocks", "Hysteria", "Hysteria2",
    "TUIC", "WireGuard/WARP", "ShadowTLS",
    "AnyTLS", "NaiveProxy", "SSH",
    "Snell", "SOCKS", "HTTP Proxy",
]


def protocol_display_names() -> list:
    """What "PC" shows. Starts from PROTOCOL_DISPLAY_LIST and appends any protocol
    the program supports (see _PROTOCOL_CANONICAL, which mirrors the parser) that
    the list forgot, so a newly added protocol can never be missing from PC."""
    names = list(PROTOCOL_DISPLAY_LIST)
    shown = " ".join(names).lower()
    for canonical in _PROTOCOL_CANONICAL.values():
        if canonical.lower() not in shown:
            names.append(canonical)
    return names


def show_protocol_list():
    """Print the complete supported protocol list in three compact columns."""
    print("\n" + _C.BOLD + _C.CYAN + "Supported Protocols" + _C.RESET)
    _render_three_columns(protocol_display_names(), lambda x: str(x))
    print()

def print_info_block(kind) -> None:
    """The country list (SC) or protocol list (PC), printed as part of the connection
    screen directly UNDER the CONNECT line - Fast Connect / Switch Server / Switch Sub /
    the prompt follow below it."""
    if kind == "country":
        print(_C.BOLD + _C.CYAN + "Available Countries" + _C.RESET)
        _render_three_columns(COUNTRY_DISPLAY_LIST, lambda item: f"{item[0]} {item[1]}")
    elif kind == "protocol":
        print(_C.BOLD + _C.CYAN + "Supported Protocols" + _C.RESET)
        _render_three_columns(protocol_display_names(), lambda x: str(x))


def _info_block_rows(kind, columns: int) -> int:
    """How many terminal rows print_info_block(kind) needs (0 for no block)."""
    if not kind:
        return 0
    counter = _RowCounter(io.StringIO(), columns)
    with contextlib.redirect_stdout(counter):
        print_info_block(kind)
    return counter.rows


def print_switch_lines(top_outbounds_count: int, tag: str = None, top_outbounds: list = None):
    """Print only the two switch controls that belong above the input area.

    The protocol/country hint and the actual Type + Enter prompt are rendered
    separately by render_connection_status(). Keeping them out of this table
    prevents the duplicate prompt that previously appeared on Termux.

    Switch Server also shows which number is the one currently connected -
    e.g. "1 - 9 (2)" means server #2 of that range is the active one - in
    green, right after the range, when `tag` is found in `top_outbounds`.
    """
    if top_outbounds_count and top_outbounds_count > 0:
        server_range = f"1 - {top_outbounds_count}"
        position = None
        if tag and top_outbounds:
            for i, ob in enumerate(top_outbounds):
                if ob.get("tag") == tag:
                    position = i + 1
                    break
        if position:
            server_range += f" {_C.GREEN}{_C.BOLD}({position}){_C.YELLOW}"
    else:
        server_range = "-"
    for label, value in (("Switch Server", server_range), ("Switch Sub", switch_sub_range())):
        print(f"  {_C.YELLOW}{_C.BOLD}{label} : {value}{_C.RESET}")


def _gap():
    """One blank spacer row. Left out in the compact layout, which
    render_connection_status() switches to when the screen is too short to fit
    the Faravahar with the normal spacing."""
    if not _state.get("compact_layout"):
        print()


PORTS_SHOWN = [3000, 60000, 50000, 10808]   # extra ports listed in the box (all extra ports stay open)


def print_ports_line():
    """'Local:127.0.0.1 Port:64808, 3000, 60000, 50000, 10808' - only ports that are really open."""
    shown = [LOCAL_SOCKS_HTTP_PORT] + [p for p in PORTS_SHOWN if p in EXTRA_PORTS]
    print(f"{OK} Local:127.0.0.1 Port:{', '.join(str(p) for p in shown)}")
    _gap()


def _plan_layout(term, extra: int = 0):
    """Decide how to draw the screen: (compact, banner_row_budget, rest_rows).
    'fit' mode first tries the normal spacing; if that leaves no room for a decent
    Faravahar it switches to the compact layout (no blank spacer rows, shorter
    ports line) so a bigger picture fits without scrolling."""
    rest_n = _state.get("rest_normal", _FARAVAHAR_REST_DEFAULT) + extra   # extra = SC/PC list rows
    rest_c = _state.get("rest_compact", _state.get("rest_normal", _FARAVAHAR_REST_DEFAULT) - _COMPACT_SAVES) + extra
    budget_n = term.lines - rest_n - 1
    if FARAVAHAR_MODE != "fit":
        return False, budget_n, rest_n
    budget_c = term.lines - rest_c - 1
    kn = _pick_faravahar(term.columns, budget_n)
    kc = _pick_faravahar(term.columns, budget_c)
    area = lambda k: k[0] * k[1] if k else 0
    if area(kc) > area(kn):
        return True, budget_c, rest_c
    return False, budget_n, rest_n


def render_connection_status(tag: str, all_outbounds: list, top_outbounds: list,
                              label: str = "Connected", fragment_preset: int = None,
                              info_block=None, reuse_info: bool = False,
                              search_web: bool = False) -> bool:
    """Redraws the whole visible pane every time a connection is
    (re)confirmed - initial connect, rescans, server switches, Fragment
    preset changes, and auto-reconnects. Uses \x1b[2J\x1b[H (clear the current
    viewport, then move the cursor home) so shorter new lines never leave old
    trailing text behind. Draws, in order: the Faravahar banner (reprinted fresh
    every time so it stays pinned to the top), the 'Connected ... server' box,
    the reachable-ports line, the command-help legend, the CONNECT block and the
    input prompt.

    The whole screen must fit the terminal: when a redraw is taller than the
    terminal, its top rows scroll off into the scrollback on every refresh and
    the banner pieces pile up there ("stacked copies"). So the banner is sized to
    the space left (measured height of everything below it), the compact layout is
    used when that gives a bigger picture, and the scrollback is cleared if the
    screen would still scroll."""
    term = shutil.get_terminal_size(fallback=(80, 24))
    extra = _info_block_rows(info_block, term.columns)   # SC / PC list shown under CONNECT
    compact, budget, rest = _plan_layout(term, extra)
    clear = "\x1b[2J"
    if _banner_rows_planned(term.columns, budget) + rest > term.lines:
        # Even the chosen banner leaves the screen taller than the terminal ("big" mode,
        # or a very short terminal): it will scroll, so drop the scrollback first,
        # otherwise the top rows of every earlier redraw pile up there as stacked copies.
        clear += "\x1b[3J"
    sys.stdout.write(clear + "\x1b[H")
    print_banner(max_rows=budget)
    counter = _RowCounter(sys.stdout, term.columns)
    _state["compact_layout"] = compact
    try:
        with contextlib.redirect_stdout(counter):
            ok = _render_status_body(tag, all_outbounds, top_outbounds, fragment_preset,
                                     info_block=info_block, reuse_info=reuse_info,
                                     search_web=search_web)
    finally:
        _state["compact_layout"] = False
    # (the SC/PC list is a temporary extra: it must not enlarge the measured normal screen)
    _state["rest_compact" if compact else "rest_normal"] = min(max(0, counter.rows - extra),
                                                              2 * _FARAVAHAR_REST_DEFAULT)
    # sizes the banner on the next redraw - clamped so one freak render (e.g. stray
    # input replayed as bogus commands corrupting a single frame) can't shrink the
    # Faravahar picture on every redraw after it; a normal frame never gets near
    # this ceiling, so the clamp is invisible in ordinary use.
    return ok


def _render_status_body(tag: str, all_outbounds: list, top_outbounds: list,
                        fragment_preset: int = None, info_block=None, reuse_info: bool = False,
                        search_web: bool = False) -> bool:
    """Everything below the banner: connection box, ports line, command legend,
    CONNECT line, Fast Connect / Switch lines and the input prompt."""
    # The standalone "Connected ...:" status line is intentionally removed.
    # The protocol title is already shown inside the connection box.
    top_outbounds_count = len(top_outbounds) if top_outbounds else 0
    ok = print_connection_info(tag, all_outbounds, fragment_preset=fragment_preset, reuse=reuse_info)
    print_ports_line()
    _state["render_tag"] = tag
    print_command_help(top_outbounds_count, _state.get("fragment_supported", False),
                       fragment_preset=fragment_preset)
    # Keep a stable two-line command area. There is intentionally NO animated
    # cursor/dot next to CONNECT: terminal redraws can pull Termux back to the
    # bottom and make scrolling the command history difficult.
    # Center CONNECT in the current Termux terminal.
    connect_text = "𝗖𝗢𝗡𝗡𝗘𝗖𝗧"
    source_label = connect_source_label(tag)  # e.g. T10 / S3 / L1: the source of this connection
    web_label = web_source_label(tag)         # SW website / Telegram channel
    if web_label:
        connect_text = _math_bold(f"CONNECT to {web_label}")   # CONNECT to freeproxydb.com / CONNECT to Telegram : VPNJEY
    elif source_label:
        connect_text = _math_bold(f'CONNECT to "{source_label}"')   # CONNECT to "T29_Telegram@vpnjey"
    connect_pad = max(0, (term_width() - len(connect_text)) // 2)
    print(" " * connect_pad + f"{_C.GREEN}{_C.BOLD}{connect_text}{_C.RESET}")
    if _state.get("ai_tag") and _state.get("ai_tag") == tag and _state.get("ai_note"):
        print("  " + f"{_C.BLUE}{_C.BOLD}" + _fit_to_width("AI ▸ " + _state["ai_note"], max(term_width() - 4, 10)) + _C.RESET)
    if info_block:
        # SC / PC: the country or protocol list sits right under CONNECT
        print_info_block(info_block)

    # Show Fast Connect state at the very bottom of the connection screen.
    # It is intentionally placed immediately ABOVE the input prompt so the
    # prompt remains the final line and the area after its colon is always
    # completely empty for the user's next command.
    fc_color = f"{_C.GREEN}{_C.BOLD}" if FAST_CONNECT_ENABLED else _C.RED
    print(f"  {fc_color}{'Fast Connect':<13} : {'ON' if FAST_CONNECT_ENABLED else 'OFF'}{_C.RESET}")
    print_switch_lines(top_outbounds_count, tag, top_outbounds)

    # One hint line followed by one real input line. The hint is informational;
    # the second line is the only place where stdin is consumed. Keeping the
    # prompt on its own line prevents the old duplicate "Type Protocol..." line
    # from visually swallowing the actual Type + Enter input area.
    if not search_web and _as_prompt_hidden():
        # Auto Setting is about to pick the best DNS + Fragment for this fresh connection:
        # no "Type + Enter" until that is done (the main loop runs it right away and then
        # redraws this screen with the prompt).
        return ok
    if search_web:
        # Same input line, same dispatch logic below it (protocol / country / ping
        # search - GitHub + Telegram sources, quality gate, silent background
        # pool-fill, source memory - all unchanged); only the prompt text differs.
        print(f"  {_C.CYAN}{_discovery_status_note()}{_C.RESET}")
        print(f"  {_C.YELLOW}{_C.BOLD}Anything: Protocol/Country/Ping/Telegram id/Site/Text : 👇{_C.RESET}")
        print(f"  {_C.BOLD}{_C.CYAN}Search Web 🔍: {_C.RESET}", end="", flush=True)
    else:
        print(f"  {_C.YELLOW}{_C.BOLD}Type Protocol, Country and Commands : 👇👇{_C.RESET}")
        print(f"  {_C.BOLD}{_C.CYAN}Type + Enter : {_C.RESET}", end="", flush=True)
    return ok


def _as_prompt_hidden() -> bool:
    """True while a fresh connection is waiting for its Auto Setting pass (best DNS + Fragment)."""
    if not (AUTO_SETTING_ENABLED and _state.get("as_full_pending")):
        return False
    p = _state.get("proc")
    try:
        return p is not None and p.poll() is None
    except Exception:
        return False


def _erase_submitted_input_line() -> None:
    """Erase the line echoed by the terminal after the user presses Enter.

    stdin is intentionally read in normal/canonical mode for reliable paste
    support in Termux, so the terminal echoes the command and advances to the
    next physical row before Python receives it.  Move back exactly one row,
    erase that submitted-input row, and return to the row below it.  This keeps
    rejected commands from creating visible blank lines and lets SC/PC print
    their output without forcing a full-screen refresh.
    """
    sys.stdout.write("\x1b[1A\x1b[2K\r\x1b[1B")
    sys.stdout.flush()


def _redraw_input_prompt_in_place() -> None:
    """Replace the just-submitted input with a clean prompt (Search Web 🔍 when SW is pending)."""
    sys.stdout.write("\x1b[1A\x1b[2K\r")
    if _state.get("sw_pending"):
        print(f"  {_C.BOLD}{_C.CYAN}Search Web 🔍: {_C.RESET}", end="", flush=True)
    else:
        print(f"  {_C.BOLD}{_C.CYAN}Type + Enter : {_C.RESET}", end="", flush=True)



def wait_with_pulse(input_queue, total_seconds: float):
    """Wait for input without redrawing the CONNECT line.

    The old pulsing CONNECT indicator has deliberately been removed because
    periodic terminal redraws interfere with upward scrolling in Termux.
    Commands remain responsive because the input queue is still polled.
    """
    interval = 0.15
    steps = max(1, int(total_seconds / interval))
    for _ in range(steps):
        try:
            return input_queue.get(timeout=interval)
        except queue.Empty:
            continue
    return None


def protocol_label(ob: dict) -> str:
    """Friendly protocol name for a parsed outbound - used in the connection
    display and in connect notifications so the user can tell at a glance
    what they're actually connected through (e.g. Cloudflare WARP looks and
    behaves very differently from a VLESS/Trojan proxy)."""
    if not ob:
        return "?"
    t = ob.get("type", "?")
    if t == "wireguard":
        tag = ob.get("tag", "")
        is_warp = tag.startswith("WARP-") or _looks_like_cloudflare_warp(ob.get("server", ""))
        return "Cloudflare WARP" if is_warp else "WireGuard"
    return {
        "vless": "VLESS",
        "trojan": "Trojan",
        "hysteria2": "Hysteria2",
        "hysteria": "Hysteria",
        "vmess": "VMess",
        "shadowsocks": "Shadowsocks",
        "tuic": "TUIC",
        "shadowtls": "ShadowTLS",
        "anytls": "AnyTLS",
        "naive": "NaiveProxy",
        "ssh": "SSH",
        "snell": "Snell",
        "socks": "SOCKS",
        "http": "HTTP Proxy",
    }.get(t, (t or "?").upper())


# ---- Per-protocol paste-format help (SubLink / L-link error messages) --------
# Ordered the same way parser.parse_proxy_uri() dispatches, so the longer/more
# specific scheme is always matched before a shorter one that could also
# prefix-match it (hysteria2:// before hy://, warp:// before wireguard:// is
# not needed since neither prefixes the other, etc.).
PROTOCOL_LINK_FORMATS = [
    ("vless://", "VLESS",
     "vless://UUID@HOST:PORT?type=tcp&security=tls&sni=example.com&fp=chrome#name"),
    ("trojan://", "Trojan",
     "trojan://PASSWORD@HOST:PORT?security=tls&sni=example.com&type=tcp#name"),
    ("hysteria2://", "Hysteria2",
     "hysteria2://PASSWORD@HOST:PORT?sni=example.com&obfs=salamander&obfs-password=xxx#name"),
    ("hy2://", "Hysteria2",
     "hy2://PASSWORD@HOST:PORT?sni=example.com&obfs=salamander&obfs-password=xxx#name"),
    ("hysteria://", "Hysteria",
     "hysteria://HOST:PORT?auth=xxx&peer=example.com&upmbps=20&downmbps=100#name"),
    ("hy://", "Hysteria",
     "hy://HOST:PORT?auth=xxx&peer=example.com&upmbps=20&downmbps=100#name"),
    ("warp://", "WireGuard/WARP",
     "warp://PRIVATE_KEY@ENGAGE.CLOUDFLARECLIENT.COM:2408?public_key=xxx&reserved=1,2,3#name"),
    ("wireguard://", "WireGuard/WARP",
     "wireguard://PRIVATE_KEY@HOST:PORT?publickey=xxx&address=10.0.0.2/32#name"),
    ("vmess://", "VMess",
     "vmess://<base64-encoded JSON config> - export it as a link from your VMess panel"),
    ("ss://", "Shadowsocks",
     "ss://BASE64(method:password)@HOST:PORT#name"),
    ("tuic://", "TUIC",
     "tuic://UUID:PASSWORD@HOST:PORT?sni=example.com&congestion_control=bbr#name"),
    ("shadowtls://", "ShadowTLS",
     "shadowtls://PASSWORD@HOST:PORT?sni=example.com&version=3#name"),
    ("anytls://", "AnyTLS",
     "anytls://PASSWORD@HOST:PORT?sni=example.com#name"),
    ("naive+https://", "NaiveProxy",
     "naive+https://USER:PASSWORD@HOST:PORT?sni=example.com#name"),
    ("naive+quic://", "NaiveProxy",
     "naive+quic://USER:PASSWORD@HOST:PORT?sni=example.com#name"),
    ("naive://", "NaiveProxy",
     "naive://USER:PASSWORD@HOST:PORT?sni=example.com#name"),
    ("ssh://", "SSH",
     "ssh://USER:PASSWORD@HOST:PORT#name"),
    ("snell://", "Snell",
     "snell://PSK@HOST:PORT?version=4&obfs=http&obfs-host=x&reuse=1#name "
     "(only v4/v5/v6 - obfs=tls is not supported)"),
    ("socks5://", "SOCKS", "socks5://USER:PASSWORD@HOST:PORT#name"),
    ("socks4a://", "SOCKS", "socks4a://USER@HOST:PORT#name"),
    ("socks4://", "SOCKS", "socks4://USER@HOST:PORT#name"),
    ("socks://", "SOCKS", "socks://USER:PASSWORD@HOST:PORT#name"),
]


def _protocol_format_hint(pasted: str):
    """Matches the scheme of a pasted link/subscription against
    PROTOCOL_LINK_FORMATS and returns (protocol_name, example_format), or
    None when the scheme is not one the parser understands at all (an
    http(s):// link is treated as a plain subscription URL, not a link
    format error, so it is intentionally not in this table)."""
    p = (pasted or "").strip()
    for scheme, name, example in PROTOCOL_LINK_FORMATS:
        if p.lower().startswith(scheme):
            return name, example
    return None


def _snapshot_optional_settings() -> dict:
    """Remember DNS / Speed Boost state so a failed new-link attempt can put it back."""
    return {"sb1": SPEED_BOOST_ENABLED, "sb2": SPEED_BOOST2_ENABLED, "dns_winner": DNS_WINNER,
            "dns_disabled": DNS_DISABLED}


def _restore_optional_settings(snap: dict):
    global SPEED_BOOST_ENABLED, SPEED_BOOST2_ENABLED, DNS_WINNER, DNS_DISABLED
    if not snap:
        return
    SPEED_BOOST_ENABLED = snap["sb1"]
    SPEED_BOOST2_ENABLED = snap["sb2"]
    DNS_WINNER = snap["dns_winner"]
    DNS_DISABLED = snap["dns_disabled"]


def _snapshot_connection(proc, last_tag, all_outbounds, top_outbounds, manual_tag) -> dict:
    """Everything needed to bring the current connection back after a failed search."""
    return {"proc": proc, "last_tag": last_tag, "all": all_outbounds, "top": top_outbounds,
            "manual": manual_tag, "free_mode": _state.get("free_vless_mode"),
            "free_src": _state.get("free_source_index"), "free_pool": _state.get("free_verified_pool"),
            "settings": _snapshot_optional_settings()}


def _restore_previous_connection(binary: str, ir_bypass_enabled: bool, fragment_preset, snap: dict):
    """After a failed search: keep the previous connection. If the old tunnel is still alive
    nothing is touched; if the search already replaced/killed it, the old server is
    reconnected. Returns (proc, last_tag, all_outbounds, top_outbounds, manual_tag)."""
    _state["free_vless_mode"] = snap["free_mode"]
    _state["free_source_index"] = snap["free_src"]
    _state["free_verified_pool"] = snap["free_pool"]
    unchanged = (snap["proc"], snap["last_tag"], snap["all"], snap["top"], snap["manual"])
    if not snap["last_tag"]:
        return unchanged
    old_proc = snap["proc"]
    if old_proc is not None and old_proc.poll() is None and _state.get("proc") is old_proc:
        return unchanged  # the search never touched the live tunnel
    try:
        kill_singbox()
        _state["cleaned_up"] = False
        _restore_optional_settings(snap["settings"])
        print(f"{INFO} Search failed - keeping your previous connection...")
        rp, rt, rok = connect_with_fallback(
            binary, snap["top"], snap["manual"] or snap["last_tag"], ir_bypass_enabled,
            snap["all"], label="Reconnected (previous connection)",
            enable_fragment=fragment_preset, reset_options=False)
        if rt and rok:
            return rp, rt, snap["all"], snap["top"], rt
    except Exception:
        pass
    return unchanged


def _countdown_then_refresh(seconds: int, last_tag: str, all_outbounds: list,
                             top_outbounds: list, fragment_preset: int = None,
                             label: str = "Connected VLESS server") -> None:
    """Shows a live, second-by-second countdown on the current line (e.g. for
    a paste-format error), then clears it and redraws the normal connection
    screen - so the error is readable for `seconds` seconds and then goes
    away by itself instead of lingering above the prompt forever."""
    for remaining in range(seconds, 0, -1):
        sys.stdout.write(
            f"\r{_C.YELLOW}{_C.BOLD}Refreshing in {remaining}s...{_C.RESET}" + " " * 12
        )
        sys.stdout.flush()
        time.sleep(1)
    sys.stdout.write("\r" + " " * 40 + "\r")
    sys.stdout.flush()
    if last_tag:
        render_connection_status(last_tag, all_outbounds, top_outbounds,
                                  label=label, fragment_preset=fragment_preset)


def short_sub_url_for_display(sub_url: str) -> str:
    """Display only the subscription hostname up to '.workers'.
    Example:
      https://mahta2049.mahta2049-625.workers.dev/sub/raw/... 
      -> mahta2049.mahta2049-625.workers
    """
    if not sub_url:
        return ""
    try:
        host = urllib.parse.urlparse(sub_url).hostname or ""
    except Exception:
        host = ""
    if not host:
        host = sub_url.replace("https://", "").replace("http://", "").split("/", 1)[0]
    marker = ".workers"
    pos = host.lower().find(marker)
    if pos >= 0:
        return host[:pos + len(marker)]
    return host.split("/", 1)[0]

_COUNTRY_FLAG_ALIASES = {
    # English / common output names -> ISO-3166 alpha-2.
    "america": "US", "united states": "US", "usa": "US",
    "england": "GB", "united kingdom": "GB", "uk": "GB", "great britain": "GB",
    "germany": "DE", "netherlands": "NL", "france": "FR", "canada": "CA",
    "switzerland": "CH", "sweden": "SE", "norway": "NO", "finland": "FI",
    "denmark": "DK", "italy": "IT", "spain": "ES", "austria": "AT",
    "belgium": "BE", "poland": "PL", "romania": "RO", "turkey": "TR",
    "japan": "JP", "singapore": "SG", "australia": "AU", "india": "IN",
    "brazil": "BR", "hong kong": "HK", "emirates": "AE",
    "united arab emirates": "AE", "uae": "AE",
}

def _iso_flag(code: str) -> str:
    code = str(code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(ch) - 65) for ch in code)


def country_flag(country_name: str, country_code: str = "") -> str:
    """Return a flag for API country output, including America/England aliases."""
    if country_code:
        flag = _iso_flag(country_code)
        if flag:
            return flag
    key = _norm_country_text(country_name)
    return _iso_flag(_COUNTRY_FLAG_ALIASES.get(key, ""))


def display_server_name(tag: str) -> str:
    """Remove internal FV/S/L numbering from the visible server name.

    Examples:
      FV-S3-145. @MetiVIP ... -> @MetiVIP ...
      S1-03. my-server       -> my-server
    """
    raw = str(tag or "").strip()
    patterns = (
        r"^FV-(?:S|F)\d+-[^.\s]+\.\s*",
        r"^S\d+-[^.\s]+\.\s*",
        r"^L\d+-[^.\s]+\.\s*",
    )
    for pattern in patterns:
        cleaned = re.sub(pattern, "", raw, count=1, flags=re.IGNORECASE)
        if cleaned != raw:
            return cleaned.strip() or raw
    # Some feeds use a numeric/source prefix without the final dot-space.
    cleaned = re.sub(r"^FV-(?:S|F)\d+-[^\s]+\s*", "", raw, count=1, flags=re.IGNORECASE)
    return cleaned.strip() or raw


_PING_EMOJI_THRESHOLDS = (
    (120, "🚀"),
    (200, "🤩"),
    (300, "😎"),
    (450, "😍"),
    (550, "😊"),
    (650, "🙂"),
    (750, "😐"),
    (850, "😟"),
    (1000, "😭"),
    (10**9, "😢"),
)

def ping_emoji(ms) -> str:
    """Ten latency faces/icons from excellent to very poor."""
    try:
        value = float(ms)
    except (TypeError, ValueError):
        return "😐"
    for limit, emoji in _PING_EMOJI_THRESHOLDS:
        if value <= limit:
            return emoji
    return "😢"


def ping_search_upper_bound(requested_ms: int) -> int:
    """Map P318 -> 350 and P400 -> 450 (next 50-ms bucket)."""
    n = max(0, int(requested_ms))
    return max(50, ((n // 50) + 1) * 50)


def ping_color(ms):
    """Green at <=450ms, then gradually transitions yellow -> orange -> red."""
    try:
        value = float(ms)
    except (TypeError, ValueError):
        return None
    if value <= 450:
        return _C.GREEN
    # Smooth interpolation from green (450ms) to red (1500ms+).
    t = max(0.0, min(1.0, (value - 450.0) / 1050.0))
    # Green -> yellow -> orange -> red, piecewise RGB.
    stops = [
        (0.00, (0, 220, 80)),
        (0.42, (255, 220, 0)),
        (0.68, (255, 165, 0)),
        (1.00, (255, 50, 50)),
    ]
    for i in range(len(stops) - 1):
        p1, c1 = stops[i]
        p2, c2 = stops[i + 1]
        if t <= p2:
            local = (t - p1) / (p2 - p1)
            rgb = tuple(round(c1[j] + (c2[j] - c1[j]) * local) for j in range(3))
            return f"\x1b[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m"
    return "\x1b[38;2;255;50;50m"

RAMIN_TITLE = "⚡R A M I N  V P N⚡"
APP_VERSION = "0.1.0"


def print_ramin_signature_line(label: str = ""):
    """Bottom line of the box: 'Version: x' centered, same width as the header."""
    middle_len = _visible_width_wide(RAMIN_TITLE) + 2
    text = f"Version: {APP_VERSION}"
    pad = max(0, middle_len - len(text))
    middle = " " * (pad // 2) + text + " " * (pad - pad // 2)
    print(f"{_C.MAGENTA}{'=' * 10}{_C.RESET}"
          f"{_C.BOLD}{middle}{_C.RESET}"
          f"{_C.MAGENTA}{'=' * 10}{_C.RESET}")


def print_connection_info(tag: str, all_outbounds: list, fragment_preset: int = None,
                          reuse: bool = False) -> bool:
    outbound_by_tag = {ob["tag"]: ob for ob in all_outbounds}
    ob = outbound_by_tag.get(tag)
    delay = get_proxy_delay(tag)
    LABEL_W = 13  # width of the connection-info labels
    # below lines up its ':' under this, instead of each line inventing
    # its own spacing (which is what let the colons drift out of column
    # before).

    def field(label, value, color=None):
        text = f"  {label:<{LABEL_W}}: {value}"
        print(f"{color}{text}{_C.RESET}" if color else text)

    def status_color(active):
        # Active status/options are always green + bold.
        # Inactive options remain red.
        return f"{_C.GREEN}{_C.BOLD}" if active else _C.RED

    def fragment_and_dns_fields():
        dns_active = bool(DNS_WINNER and not DNS_DISABLED)
        if dns_active:
            field("DNS", f"{DNS_WINNER['name']} ({DNS_WINNER['ip']}) - {DNS_WINNER['proto']}", status_color(True))
        else:
            field("DNS", "OFF", status_color(False))

        speed_boost_active = bool(SPEED_BOOST_ENABLED or SPEED_BOOST2_ENABLED)
        field("Speed Boost", "ON" if speed_boost_active else "OFF", status_color(speed_boost_active))

        if fragment_preset:
            fname = FRAGMENT_PRESETS.get(fragment_preset, {}).get("name", str(fragment_preset))
            field("Fragment", f"{fname} (ON)", status_color(True))
        else:
            field("Fragment", "OFF", status_color(False))

    label = protocol_label(ob)
    bar = f"{_C.MAGENTA}{'=' * 10}{_C.RESET}"
    _gap()
    print(f"{bar} {_C.BOLD}{RAMIN_TITLE}{_C.RESET} {bar}")
    sub_url = get_subscription_url_for_tag(tag)
    if sub_url:
        field("Sub URL", short_sub_url_for_display(sub_url), None)
    # Free Vless / Fast Connect are intentionally not shown in the connection-info box.
    # Their state remains available in the Commands section.
    field("Name", display_server_name(tag))
    field("Protocol", f"{_C.GREEN}{_C.BOLD}{str(label or 'Unknown').upper()}{_C.RESET}")
    if ob:
        host = str(ob['server'])
        host = f"[{host}]" if ":" in host and not host.startswith("[") else host   # IPv6 literal
        field("Address", f"{host}:{ob['server_port']}")
    if delay is not None:
        ping_text = f"{delay:.0f} ms {ping_emoji(delay)}"
        ping_col = ping_color(delay) or _C.GREEN
        print(f"  {"Ping":<{LABEL_W}}: {_C.BOLD}{ping_col}{ping_text}{_C.RESET}")
    else:
        field("Ping", "not measured yet")

    # PRIMARY SUCCESS CRITERION: the selected outbound must complete a real
    # proxied HTTP test through sing-box. Public-IP/geolocation lookup can
    # time out or be blocked without meaning the VLESS tunnel is broken.
    # reuse=True (SC/PC list, the "pool is full" redraw): same tunnel, nothing changed, so the
    # results of the last probe are shown again instead of testing and looking up the IP again.
    cached = _state.get("info_cache")
    ckey = (tag, id(_state.get("proc")))
    if reuse and cached and cached.get("key") == ckey and time.monotonic() - cached["ts"] < 900:
        proxy_ok, proxy_delay, proxy_error = True, cached["proxy_delay"], None
        info = cached["info"]
    else:
        cached = None
        with Spinner("Checking real proxy connection...") as sp:
            proxy_ok, proxy_delay, proxy_error = probe_proxy_connectivity(tag)
            sp.failed = not proxy_ok

    if not proxy_ok:
        print(f"  {WARN} Proxy test failed: {proxy_error}")
        fragment_and_dns_fields()
        print_ramin_signature_line(label)
        _gap()
        return False

    if proxy_delay is not None:
        # Show only the measured latency and the same ten-level emoji scale.
        field("Proxy Test", f"{_C.BOLD}{_C.GREEN}{round(proxy_delay)} ms {ping_emoji(proxy_delay)}{_C.RESET}")

    # Public IP is informational only. It can NEVER make a healthy node fail.
    if cached is None:
        with Spinner("Checking public exit IP through the proxy...") as sp:
            info = fetch_public_ip_info()
            sp.failed = "error" in info
        if "error" not in info:
            _state["info_cache"] = {"key": ckey, "ts": time.monotonic(),
                                    "proxy_delay": proxy_delay, "info": info}

    if "error" in info:
        print(f"  {WARN} Public IP info unavailable (connection is still OK): {info['error']}")
    else:
        field("Public IP", info.get('query', '?'))
        country_name = info.get('country', '?')
        flag = country_flag(country_name, info.get('countryCode', ''))
        field("Country", f"{country_name} {flag}".rstrip())
        field("City", info.get('city', '?'))
        field("ISP", info.get('isp', '?'))
        field("Org", info.get('org', '?'))
    fragment_and_dns_fields()
    # Matching RAMIN VPN signature line under the connection details.
    print_ramin_signature_line(label)
    _gap()
    return True


def wait_for_selection(timeout: float = 30):
    """Polls sing-box's Clash API until 'auto' has picked a server."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        tag = get_current_selection()
        if tag:
            return tag
        time.sleep(1)
    return None


def choose_servers(all_outbounds: list, binary: str, counter: "StepCounter" = None, strict_real: bool = False):
    """Runs the full test + real connectivity check + geolocation, keeps
    only servers whose ISP, country, city AND org all resolved
    successfully. Startup selection is automatic (always server #1, the
    fastest verified one) - no prompt, no waiting for input. You can still
    switch servers anytime later by typing a number (1-50) + Enter while
    the script is running.

    counter, if given, is a StepCounter shared with the rest of the
    startup pipeline (Ports/Fetch/Find/.../Connect/...) so the TCP/TLS/
    Verify/Geo steps here keep numbering in sequence with it (e.g.
    "TCP 4/10"). If not given (e.g. a manual rescan later on), a
    standalone 4-step counter is used instead."""
    if counter is None:
        counter = StepCounter(["TCP", "TLS", "Verify", "Geo"])

    if strict_real:
        # Used only by Free Vless/SubLink. Test every parsed config
        # directly with sing-box; do not pre-filter by raw TCP/TLS ping.
        ranked = [(ob, 0.0) for ob in all_outbounds]
        verified = verify_candidates_extended(
            binary, ranked, TOP_N, label="Verify", max_candidates=len(ranked),
            test_urls=[
                "https://www.gstatic.com/generate_204",
                "https://www.google.com/generate_204",
                "https://cp.cloudflare.com/generate_204",
            ]
        )
    else:
        # Built-in S1-S8 path: intentionally keep the original pipeline.
        ranked = rank_and_select_top(all_outbounds, TOP_N, tcp_label=counter.next(), tls_label=counter.next())
        if not ranked:
            print(f"{WARN} None of the servers responded to the latency test.")
            return None, None
        verified = verify_candidates_real(binary, ranked, TOP_N, label=counter.next())

    if verified:
        ranked = verified
    else:
        print(f"{WARN} The real connectivity check failed for every candidate - "
              f"falling back to latency-only ranking (some may not actually work).")

    with Spinner(counter.next()) as sp:
        geo_by_tag = geolocate_servers(ranked)
        sp.failed = not geo_by_tag

    complete = [(ob, lat) for ob, lat in ranked if geo_is_complete(geo_by_tag.get(ob["tag"]))]
    top_with_latency = complete[:TOP_N]

    if not top_with_latency:
        print(f"{WARN} No server had complete ISP/country/city/org info - falling back to ping-only ranking.")
        top_with_latency = ranked[:TOP_N]
    elif len(top_with_latency) < TOP_N:
        print(f"{INFO} Only {len(top_with_latency)} of {len(ranked)} tested servers had full "
              f"ISP/country/city/org info - showing those.")

    print_selection_table(top_with_latency)
    manual_tag = top_with_latency[0][0]["tag"]  # auto-connect to #1, no prompt
    print_transient(f"{OK} Auto-connecting to #1: {manual_tag}")
    print_transient(f"{OK} (you can switch anytime - just type a number 1-{len(top_with_latency)} + Enter)")
    top_outbounds = [ob for ob, _ in top_with_latency]
    return top_outbounds, manual_tag




def start_singbox(binary: str, top_outbounds: list, manual_tag, enable_ir_bypass: bool,
                   all_outbounds: list, label: str = "Connected", show_info: bool = True,
                   enable_fragment: int = None, reset_options: bool = True):
    """Writes the config, starts sing-box, and returns (proc, last_tag, ok).

    The PRIMARY success criterion is a real proxied HTTP connectivity test
    through the selected outbound. Public-IP/geolocation lookup is only
    informational and must never reject an otherwise working VLESS node.

    show_info=False skips printing the full 'Connected VLESS server' box and
    performs the same real proxy connectivity test quietly/transiently.

    enable_fragment, when set to 1-4, is which FRAGMENT_PRESETS entry to
    apply for this connection."""
    if reset_options:
        reset_optional_settings_for_connection()
    config = build_singbox_config(top_outbounds, enable_ir_bypass=enable_ir_bypass,
                                   manual_tag=manual_tag, enable_fragment=enable_fragment)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    proc = subprocess.Popen([binary, "run", "-c", CONFIG_PATH], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    register_proc(proc)

    if manual_tag:
        time.sleep(3)  # brief pause for sing-box to finish starting
        last_tag = manual_tag
    else:
        last_tag = wait_for_selection()

    if last_tag:
        if show_info:
            ok = render_connection_status(last_tag, all_outbounds, top_outbounds, label=label,
                                           fragment_preset=enable_fragment)
        else:
            with Spinner("Checking VLESS connection...") as sp:
                ok, _delay, _error = probe_proxy_connectivity(last_tag)
                sp.failed = not ok
    else:
        print(f"{WARN} Could not confirm the selection yet - it'll show up on the next check.")
        ok = False

    if last_tag:
        _ai_ob = next((o for o in all_outbounds if o.get("tag") == last_tag), None)
        if _ai_ob:
            AI.record(_ai_ob, bool(ok))

    if ok and FAST_CONNECT_ENABLED and last_tag:
        ob = next((o for o in all_outbounds if o.get("tag") == last_tag), None)
        if ob:
            save_fast_connect_state(last_tag, ob, _state.get("free_vless_mode", False), _state.get("free_source_index"))

    return proc, last_tag, ok


class _SwitchRetryDisplay:
    """Two-row progress shown while _connect_trying_tags works through
    fallback candidates after the first (preferred) one turned out to be
    dead: a fixed 'Connection Failed, Please wait...' line, with a live
    'Loading [bar] NN%' line under it. Uses the exact same safe two-row
    cursor-redraw technique as FreeWaitDisplay so it can't scroll or drift
    in Termux."""
    BAR_MAX = 24
    BAR_MIN = 6

    def __init__(self, total):
        self.total = max(1, int(total))
        self.done = 0

    def _bar_line(self):
        pct = int(self.done * 100 / self.total)
        width = max(term_width(), 20)
        prefix_plain, suffix_plain = "Loading [", f"] {pct:3d}%"
        fixed = _visible_len(prefix_plain) + _visible_len(suffix_plain)
        bar_width = min(self.BAR_MAX, max(self.BAR_MIN, width - fixed - 1))
        filled = int(bar_width * self.done / self.total)
        bar = "█" * filled + "░" * (bar_width - filled)
        return f"Loading [{_C.CYAN}{bar}{_C.RESET}] {pct:3d}%"

    def start(self):
        sys.stdout.write(
            CLEAR_LINE + f"{_C.YELLOW}😔Connection Failed, Please wait...{_C.RESET}"
            + "\n" + CLEAR_LINE + self._bar_line()
        )
        sys.stdout.flush()
        return self

    def update(self, done):
        self.done = min(done, self.total)
        sys.stdout.write(
            "\x1b[1A" + CLEAR_LINE + f"{_C.YELLOW}😔Connection Failed, Please wait...{_C.RESET}"
            + "\n" + CLEAR_LINE + self._bar_line()
        )
        sys.stdout.flush()

    def stop(self):
        sys.stdout.write(CLEAR_LINE + "\x1b[1A" + CLEAR_LINE + "\x1b[1B\r")
        sys.stdout.flush()


def _connect_trying_tags(binary: str, top_outbounds: list, ordered_tags: list, enable_ir_bypass: bool,
                          all_outbounds: list, label: str = "Connected", show_info: bool = True,
                          enable_fragment: int = None, reset_options: bool = True):
    """Core connect loop: tries each tag in ordered_tags in turn, stopping at
    the first one that passes the real proxied connectivity check. Shared by
    connect_with_fallback (rank-order fallback) and
    connect_with_sequential_fallback (next-number fallback for manual picks).

    The first (preferred) candidate is shown normally. If it's dead, every
    candidate after that is tried quietly behind a single two-row
    'Connection Failed, Please wait... / Loading [bar] NN%' display instead
    of a noisy per-attempt status box or warning line."""
    proc, last_tag, ok = None, None, False
    display = None
    try:
        for i, tag in enumerate(ordered_tags):
            if proc:
                kill_singbox()
                _state["cleaned_up"] = False
            attempt_show_info = show_info and i == 0
            proc, last_tag, ok = start_singbox(
                binary, top_outbounds, tag, enable_ir_bypass, all_outbounds,
                label=label if i == 0 else "Reconnected", show_info=attempt_show_info,
                enable_fragment=enable_fragment, reset_options=(reset_options and i == 0)
            )
            if ok and _state.get("require_isp_org") and not _exit_has_isp_org():
                print_transient(f"{WARN} Rejected {last_tag}: no ISP/Org info on exit IP (security)")
                ok = False
            if ok:
                break
            if tag is None:
                break  # auto mode: nothing more to try manually
            if i == 0 and i + 1 < len(ordered_tags):
                display = _SwitchRetryDisplay(len(ordered_tags) - 1).start()
            elif display:
                display.update(i)
    finally:
        if display:
            display.stop()

    if not ok:
        print(f"{WARN} None of the candidates passed the real proxy connectivity test - staying on the last one tried.")
    return proc, last_tag, ok


def connect_with_fallback(binary: str, top_outbounds: list, preferred_tag, enable_ir_bypass: bool,
                           all_outbounds: list, label: str = "Connected", show_info: bool = True,
                           enable_fragment: int = None, reset_options: bool = True):
    """Connects to preferred_tag (or lets sing-box auto-pick if None). If the
    real proxy connectivity test fails, automatically tries the next-best
    candidates instead of getting stuck on a broken one. Public-IP lookup
    is not used as a success/failure criterion."""
    if preferred_tag:
        ordered_tags = [preferred_tag] + [ob["tag"] for ob in top_outbounds if ob["tag"] != preferred_tag]
    else:
        ordered_tags = [None]  # single attempt, sing-box auto-picks
    return _connect_trying_tags(binary, top_outbounds, ordered_tags, enable_ir_bypass, all_outbounds,
                                 label, show_info=show_info, enable_fragment=enable_fragment,
                                 reset_options=reset_options)


def connect_with_sequential_fallback(binary: str, top_outbounds: list, start_idx: int, enable_ir_bypass: bool,
                                      all_outbounds: list, label: str = "Connected", show_info: bool = True,
                                      enable_fragment: int = None, reset_options: bool = True):
    """Used for a manual number pick (1-50): if #start_idx+1 fails, tries
    #start_idx+2, #start_idx+3, ... in ascending order (wrapping back to #1
    after #50) instead of restarting the whole ranked list from #1."""
    n = len(top_outbounds)
    ordered_tags = [top_outbounds[(start_idx + i) % n]["tag"] for i in range(n)]
    return _connect_trying_tags(binary, top_outbounds, ordered_tags, enable_ir_bypass, all_outbounds,
                                 label, show_info=show_info, enable_fragment=enable_fragment,
                                 reset_options=reset_options)



def auto_failover_to_builtin_subscriptions(binary: str, ir_bypass_enabled: bool = False):
    """Automatic replacement for a failed / deleted custom Link: connect through the
    Free Vless (FV) chain, starting at T1. (Name kept for the existing callers;
    the old S1-S8 subscriptions no longer exist.)
    Returns (proc, tag, ok, all_outbounds, top_outbounds, manual_tag, None)."""
    disable_speed_and_fragment()
    _release_country_binding()
    _state["current_sub_index"] = None
    print(f"{WARN} Link connection failed - switching to Free Vless (FV)...")
    kill_singbox()
    _state["cleaned_up"] = False
    proc, tag, ok, top, manual, _idx = connect_free_vless_with_failover(
        binary, ir_bypass_enabled=False, first_source_index=0, enable_fragment=None)
    if tag and ok and top:
        _state["free_vless_mode"] = True
        return proc, tag, True, top, top, manual or tag, None
    _state["free_vless_mode"] = True
    return proc, tag, False, None, None, None, None


class _NullWaitDisplay:
    """No-visible-output stand-in for FreeWaitDisplay, so
    _verify_fv_sublink_isolated runs its normal isolated-verification logic
    without drawing any progress bar - used by Auto Setting, which must
    never print or show anything on screen."""
    def tick(self, n=1):
        pass

    def add_success(self):
        pass

    def set_progress_total(self, n):
        pass

    def stop(self, final_count=None, clear=True):
        pass


# ---- Auto Setting engine -----------------------------------------------------
AUTO_SETTING_INTERVAL_SECONDS = 15 * 60  # kept for _auto_setting_cycle(full=False)'s own use if ever
# called again, but NOTHING in the main loop triggers a periodic DNS-only recheck anymore (see
# AUTO_SETTING_FULL_DELAY_SECONDS below) - a fresh connection gets exactly one full DNS+Fragment
# pass, 3 minutes after it connects, and nothing further until the next fresh connection.
AUTO_SETTING_FULL_DELAY_SECONDS = 0  # (was 3 min) the pass now runs immediately after a fresh connection; wait this long after a fresh connection before picking
# its best DNS + Fragment, so the pass runs once the connection has had a moment to settle rather
# than the instant it comes up.
AUTO_SETTING_PING_THRESHOLD_MS = 800  # only recover the server when the real proxy ping is worse than this
AUTO_DNS_SWITCH_RATIO = 0.85  # while running, switch DNS only if the best one is >= 15% faster than the one
# in use (or the one in use stopped answering). Every switch restarts the tunnel and drops the user's live
# connections, so two providers that are a few ms apart must never make it flip back and forth.

# Fragment test (once per fresh connection): the connected server is run in isolated temporary
# sing-box processes - the live tunnel is never touched - once WITHOUT fragment and once with every
# FRAGMENT_PRESETS entry; each makes AUTO_FRAGMENT_PROBES real requests, every one on a brand-new
# connection, so the TLS handshake with the server (the part Fragment changes) is what gets timed.
AUTO_FRAGMENT_PROBES = 4
AUTO_FRAGMENT_PROBE_TIMEOUT = 6.0  # seconds one probe may take
AUTO_FRAGMENT_WORKERS = 3  # temporary sing-box processes running at once
AUTO_FRAGMENT_TIE_RATIO = 0.15  # presets whose median is within 15% (+ TIE_MS) of the fastest count as tied ...
AUTO_FRAGMENT_TIE_MS = 25  # ... and the lightest of the tied presets (F1 before F2 ...) wins


def _fragment_probe_server(binary: str, ob: dict, preset_id, probes: int = AUTO_FRAGMENT_PROBES,
                           timeout: float = AUTO_FRAGMENT_PROBE_TIMEOUT) -> dict:
    """Run `ob` alone in a temporary sing-box (optionally with Fragment preset `preset_id`;
    0/None = no Fragment) and time `probes` real requests through it.

    Returns {"ok": successful probes, "fails": failed probes, "median_ms": median latency of the
    successful ones or None}. Any problem (config rejected, sing-box did not start, server dead)
    simply counts as failed probes - this function never raises."""
    import statistics
    stats = {"ok": 0, "fails": probes, "median_ms": None}
    tag = ob.get("tag", "candidate")
    proc = None
    tmp_path = None
    try:
        listen_port = _pick_ephemeral_port()
        tmp_path = f"{CONFIG_PATH}.frag.{os.getpid()}.{listen_port}.json"
        rules = [fragment_route_rule(preset_id)] if preset_id in FRAGMENT_PRESETS else []
        config = {
            "log": {"level": "fatal"},
            "inbounds": [{"type": "mixed", "tag": "test-in", "listen": "127.0.0.1", "listen_port": listen_port}],
            "outbounds": [dict(ob), {"type": "direct", "tag": "direct"}],
            "route": {"rules": rules, "final": tag, "default_domain_resolver": "dns-direct"},
            "dns": {
                "servers": [{"type": "https", "tag": "dns-direct", "server": "1.1.1.1"}],
                "final": "dns-direct",
                "strategy": "prefer_ipv4",
            },
        }
        apply_endpoints(config)
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)
        cp = subprocess.run([binary, "check", "-c", tmp_path], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=12)
        if cp.returncode != 0:
            return stats
        proc = subprocess.Popen([binary, "run", "-c", tmp_path], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        _FV_TEST_PROCS.add(proc)
        ready = False
        deadline = time.monotonic() + 4.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return stats
            try:
                with socket.create_connection(("127.0.0.1", listen_port), timeout=0.25):
                    ready = True
                    break
            except OSError:
                time.sleep(0.08)
        if not ready:
            return stats

        proxy = f"http://127.0.0.1:{listen_port}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        delays, misses = [], 0
        for i in range(probes):
            url = FV_QUALITY_PROBE_URLS[i % len(FV_QUALITY_PROBE_URLS)]
            t0 = time.monotonic()
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "RaminVPN-AutoFragment/1.0", "Cache-Control": "no-cache"})
                with opener.open(req, timeout=timeout) as resp:
                    _ = resp.status
                delays.append((time.monotonic() - t0) * 1000.0)
            except Exception:
                misses += 1
                if not delays and misses >= 2:
                    break  # two misses and not a single success: no point waiting for the rest
        if delays:
            stats = {"ok": len(delays), "fails": probes - len(delays), "median_ms": statistics.median(delays)}
        return stats
    except Exception:
        return stats
    finally:
        if proc is not None:
            _FV_TEST_PROCS.discard(proc)
            try:
                proc.terminate()
                proc.wait(timeout=1.5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if tmp_path:
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def _choose_fragment(results: dict, force_on: bool = False):
    """Pick the best Fragment from measured results {0: no-fragment, 1..4: presets}, each
    {"ok", "fails", "median_ms"}. Returns (decided, preset_id):

      (True, 1..4)  the best preset: fewest failed probes first, then lowest median latency;
                    presets within AUTO_FRAGMENT_TIE_RATIO/TIE_MS of the fastest count as tied
                    and the lightest one wins (less delay, less risk);
      (True, None)  Fragment does not help this server (every preset failed while plain worked,
                    or plain was clearly more reliable) - leave it OFF;
      (False, None) nothing worked at all (phone offline / server dead): the test proves nothing,
                    so the caller keeps the current setting and tries again later.

    force_on=True (used by Auto Setting): Fragment must end up ENABLED whenever at least one
    preset works - the best preset is taken even if plain (no Fragment) measured a bit better."""
    base = results.get(0)
    good = {pid: r for pid, r in results.items() if pid and r and r["ok"] > 0}
    if not good:
        return (True, None) if (base and base["ok"] > 0) else (False, None)
    best_fails = min(r["fails"] for r in good.values())
    if base and base["ok"] > 0 and base["fails"] < best_fails and not force_on:
        return True, None
    pool = {pid: r for pid, r in good.items() if r["fails"] == best_fails}
    best_median = min(r["median_ms"] for r in pool.values())
    limit = best_median * (1.0 + AUTO_FRAGMENT_TIE_RATIO) + AUTO_FRAGMENT_TIE_MS
    for pid in sorted(pool):
        if pool[pid]["median_ms"] <= limit:
            return True, pid
    return True, min(pool, key=lambda pid: pool[pid]["median_ms"])  # unreachable safety net


def select_best_fragment(binary: str, ob: dict, force_on: bool = False):
    """Measure "no Fragment" and every Fragment preset on server `ob` (see
    _fragment_probe_server) and return _choose_fragment()'s (decided, preset_id)."""
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=AUTO_FRAGMENT_WORKERS) as executor:
        futures = {executor.submit(_fragment_probe_server, binary, ob, pid): pid
                   for pid in [0] + sorted(FRAGMENT_PRESETS)}
        for future in concurrent.futures.as_completed(futures):
            pid = futures[future]
            try:
                results[pid] = future.result()
            except Exception:
                results[pid] = {"ok": 0, "fails": AUTO_FRAGMENT_PROBES, "median_ms": None}
    return _choose_fragment(results, force_on=force_on)


def _auto_dns_choice(results: list, current, rejected=None):
    """Which DNS Auto Setting should switch to, or None to keep what it has.

    results  : race_dns_results_via_tunnel(), fastest first
    current  : the DNS_WINNER dict in use, or None when tunnel DNS is off
    rejected : (ip, proto) of a DNS that failed to hold a real connection earlier - never retried

    With no DNS in use the fastest one is taken. With one in use it is replaced only when it
    stopped answering, or the fastest is at least (1 - AUTO_DNS_SWITCH_RATIO) faster."""
    if not results:
        return None
    usable = [r for r in results if (r["ip"], r["proto"]) != rejected] if rejected else list(results)
    if not usable:
        return None
    best = usable[0]
    if not current:
        return best
    cur = next((r for r in results if r["ip"] == current.get("ip") and r["proto"] == current.get("proto")), None)
    if cur is None:
        return best  # the DNS in use no longer answers
    if (best["ip"], best["proto"]) == (cur["ip"], cur["proto"]):
        return None
    return best if best["latency_ms"] <= cur["latency_ms"] * AUTO_DNS_SWITCH_RATIO else None


@contextlib.contextmanager
def _silenced_stdout():
    """Swallow everything printed inside the block (spinners, warnings, retry
    bars...). Auto Setting runs in the middle of the live screen, so any text
    it printed used to stay stuck under the prompt (e.g. 'Checking VLESS
    connection...') while the panel above it was already out of date."""
    old = sys.stdout
    try:
        with open(os.devnull, "w") as sink:
            sys.stdout = sink
            yield
    finally:
        sys.stdout = old


def _auto_setting_due() -> bool:
    """True when the periodic (15-minute) DNS pass should run now."""
    last = _state.get("auto_setting_last_check")
    return last is None or (time.monotonic() - last) >= AUTO_SETTING_INTERVAL_SECONDS


def _auto_setting_signature(last_tag, proc, fragment_preset=None):
    """Cheap fingerprint of what the screen shows (server, tunnel process, DNS, Fragment),
    used to decide whether the panel must be redrawn after a silent pass."""
    dns = None if (DNS_DISABLED or not DNS_WINNER) else (DNS_WINNER.get("ip"), DNS_WINNER.get("proto"))
    return (last_tag, id(proc), dns, fragment_preset)


def _auto_setting_cycle(binary: str, last_tag: str, top_outbounds: list, all_outbounds: list,
                         manual_tag, fragment_preset, full: bool = False):
    """One Auto Setting pass. Never prints anything (callers silence it) and never shows a
    warning - from the user's side the tunnel just keeps working.

    full=True  - a FRESH connection (program (re)started, or the server / source / subscription
                 changed, or the user just switched AS on): pick the best DNS and the best
                 Fragment and apply both with a single tunnel restart.
    full=False - the periodic pass, every AUTO_SETTING_INTERVAL_SECONDS: DNS only. Fragment is
                 NOT re-measured here (the exception: a fresh-connection test that could not
                 decide is repeated), then the connection health steps below run.

    1. DNS  - every provider is raced through the LIVE tunnel (read-only) and applied when it
              beats the one in use by AUTO_DNS_SWITCH_RATIO (see _auto_dns_choice).
    2. Fragment (full pass only) - see select_best_fragment.
    3. (periodic only) the real proxy ping is measured; below AUTO_SETTING_PING_THRESHOLD_MS
       nothing else happens. Otherwise the rest of the current Switch Server pool is tested in
       isolation and, if a healthy one exists, the tunnel moves to it; failing that the silent
       Free Vless reserve is used. A new server is flagged for its own full pass.

    Returns (proc, last_tag, top_outbounds, all_outbounds, manual_tag, fragment_preset) -
    unchanged unless something above actually improved things."""
    global DNS_WINNER, DNS_DISABLED
    proc = _state.get("proc")
    _state["as_full_pending"] = False
    if not last_tag:
        return proc, last_tag, top_outbounds, all_outbounds, manual_tag, fragment_preset

    # 1) DNS - raced through the live tunnel, no reconnect needed just to test.
    dns_results = []
    for _attempt in range(3 if full else 1):
        try:
            dns_results = race_dns_results_via_tunnel()
        except Exception:
            dns_results = []
        if dns_results:
            break
        time.sleep(2.0)   # the tunnel was just rebuilt: give it a moment, DNS has to get enabled
    current_dns = None if (DNS_DISABLED or not DNS_WINNER) else DNS_WINNER
    new_dns = _auto_dns_choice(dns_results, current_dns, _state.get("auto_dns_rejected"))

    # 2) Fragment - measured in isolation, never on the live tunnel.
    new_fragment = fragment_preset
    if _state.get("fragment_supported") and (full or _state.get("as_fragment_pending")):
        server = next((o for o in list(all_outbounds) + list(top_outbounds) if o.get("tag") == last_tag), None)
        if server is not None:
            try:
                # Auto Setting: Fragment has to be ON afterwards (best preset), not just "maybe"
                decided, best_fragment = select_best_fragment(binary, server, force_on=True)
            except Exception:
                decided, best_fragment = False, None
            _state["as_fragment_pending"] = not decided  # inconclusive -> repeated by the next periodic pass
            if decided:
                new_fragment = best_fragment

    # 3) Apply DNS and Fragment together: ONE tunnel restart.
    dns_changed = False
    if new_dns is not None or new_fragment != fragment_preset:
        prev_dns, prev_dns_disabled, prev_fragment = DNS_WINNER, DNS_DISABLED, fragment_preset
        if new_dns is not None:
            DNS_WINNER = new_dns
            DNS_DISABLED = False
        kill_singbox()
        _state["cleaned_up"] = False
        new_proc, new_tag, new_ok = connect_with_fallback(
            binary, top_outbounds, manual_tag, False, all_outbounds,
            show_info=False, enable_fragment=new_fragment, reset_options=False
        )
        if new_ok and new_tag:
            proc, last_tag, fragment_preset = new_proc, new_tag, new_fragment
            dns_changed = new_dns is not None
            if manual_tag:
                manual_tag = new_tag
            _state["auto_dns_rejected"] = None
        else:
            # The tunnel did not pass the real proxy test with the new DNS / Fragment (slow or
            # unstable line). Never leave the user on that: put everything back, restore the
            # tunnel, and remember not to keep retrying the same DNS every cycle.
            if new_dns is not None:
                _state["auto_dns_rejected"] = (new_dns["ip"], new_dns["proto"])
            DNS_WINNER, DNS_DISABLED = prev_dns, prev_dns_disabled
            kill_singbox()
            _state["cleaned_up"] = False
            back_proc, back_tag, _back_ok = connect_with_fallback(
                binary, top_outbounds, manual_tag, False, all_outbounds,
                show_info=False, enable_fragment=prev_fragment, reset_options=False
            )
            if back_proc is not None:
                proc = back_proc
            if back_tag:
                last_tag = back_tag
                if manual_tag:
                    manual_tag = back_tag
            return proc, last_tag, top_outbounds, all_outbounds, manual_tag, fragment_preset

    if full:
        return proc, last_tag, top_outbounds, all_outbounds, manual_tag, fragment_preset

    # 4) Ping check (after any DNS change above).
    try:
        ping_ok, delay_ms, _err = probe_proxy_connectivity(last_tag)
    except Exception:
        ping_ok, delay_ms = False, None
    if ping_ok and delay_ms is not None and delay_ms <= AUTO_SETTING_PING_THRESHOLD_MS:
        return proc, last_tag, top_outbounds, all_outbounds, manual_tag, fragment_preset

    if dns_changed:
        # DNS just changed this cycle - give it until the next cycle before
        # also trying a server switch, so one cycle never does both at once.
        return proc, last_tag, top_outbounds, all_outbounds, manual_tag, fragment_preset

    # 5) Ping is still bad and DNS didn't help: test the rest of the current
    # pool, fully isolated from the live tunnel. label != "FV_WAIT" plus a
    # supplied wait_display keeps this path fully silent (no progress bar,
    # no printed failure summary) - see _NullWaitDisplay.
    rest = [ob for ob in top_outbounds if ob.get("tag") != last_tag]
    try:
        verified = _verify_fv_sublink_isolated(
            binary, [(ob, 0.0) for ob in rest], 1, label="AutoSetting",
            test_urls=["https://www.gstatic.com/generate_204",
                       "https://cp.cloudflare.com/generate_204",
                       "https://www.google.com/generate_204"],
            wait_display=_NullWaitDisplay(),
        ) if rest else []
    except Exception:
        verified = []
    if verified and verified[0][1] * 1000 <= AUTO_SETTING_PING_THRESHOLD_MS:
        best_ob = verified[0][0]
        kill_singbox()
        _state["cleaned_up"] = False
        new_proc, new_tag, new_ok = start_singbox(
            binary, top_outbounds, best_ob.get("tag"), False, all_outbounds,
            label="Reconnected", show_info=False, enable_fragment=fragment_preset, reset_options=False
        )
        if new_ok and new_tag:
            if manual_tag:
                manual_tag = new_tag
            _state["as_full_pending"] = True  # new server -> it gets its own best Fragment
            return new_proc, new_tag, top_outbounds, all_outbounds, manual_tag, fragment_preset
        return proc, last_tag, top_outbounds, all_outbounds, manual_tag, fragment_preset

    # 6) Nothing in the pool helps either: hand off to the same silent
    # background reserve FV already keeps topped up (see reserve_failover
    # and _init_reserve) - it re-verifies quietly (no FreeWaitDisplay/progress
    # bar) and only touches the live tunnel once a winner is confirmed.
    # This becomes the new Switch Server range only if it actually connects.
    if _RESERVE is not None and _RESERVE.count() > 0:
        try:
            res = reserve_failover(binary, _RESERVE, show_info=False, label="Reconnected")
        except Exception:
            res = None
        if res:
            new_proc, new_tag, new_ok, new_pool, new_manual = res
            if new_ok and new_tag:
                _state["as_full_pending"] = True
                return new_proc, new_tag, new_pool, new_pool, new_manual, None

    return proc, last_tag, top_outbounds, all_outbounds, manual_tag, fragment_preset


def measure_fragment_results(binary: str, ob: dict) -> dict:
    """{0: no Fragment, 1..4: presets} -> {"ok","fails","median_ms"} measured on server `ob`
    in isolated temporary sing-box processes (the live tunnel is never touched)."""
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=AUTO_FRAGMENT_WORKERS) as executor:
        futures = {executor.submit(_fragment_probe_server, binary, ob, pid): pid
                   for pid in [0] + sorted(FRAGMENT_PRESETS)}
        for future in concurrent.futures.as_completed(futures):
            pid = futures[future]
            try:
                results[pid] = future.result()
            except Exception:
                results[pid] = {"ok": 0, "fails": AUTO_FRAGMENT_PROBES, "median_ms": None}
    return results


def _ai_pick_dns(results: list, use_ai: bool):
    """results = one transport's race result, fastest first. Gemini reorders the measured
    entries; its pick is only accepted when it is within 1.5x + 20 ms of the fastest one, so a
    wrong answer can never leave you on a clearly slower DNS."""
    best = results[0]
    if not use_ai or len(results) < 2:
        return best
    top = results[:6]
    rows = [{"id": f"d{i + 1}", "provider": r["name"], "ip": r["ip"], "proto": r["proto"],
             "latency_ms": round(r["latency_ms"]), "past_wins": AI.dns_wins(r)}
            for i, r in enumerate(top)]
    order, _reason = claude_rank_rows(CLAUDE_TUNE_SYSTEM, rows)
    by_id = {row["id"]: r for row, r in zip(rows, top)}
    limit = best["latency_ms"] * 1.5 + 20
    for cid in order or []:
        cand = by_id.get(cid)
        if cand is not None and cand["latency_ms"] <= limit:
            return cand
    return best


def _ai_pick_fragment(results: dict, use_ai: bool):
    """(decided, preset_id or None). Local rule first (_choose_fragment); Gemini may pick another
    measured entry only when it has no more failures and is within 25% + 30 ms of the fastest."""
    decided, local = _choose_fragment(results, force_on=False)
    if not decided or not use_ai:
        return decided, local
    cands = {pid: r for pid, r in results.items()
             if r and r.get("ok", 0) > 0 and r.get("median_ms") is not None}
    if len(cands) < 2:
        return decided, local
    best_fails = min(r["fails"] for r in cands.values())
    best_med = min(r["median_ms"] for r in cands.values() if r["fails"] == best_fails)
    names = {0: "none"}
    names.update({pid: p["name"] for pid, p in FRAGMENT_PRESETS.items()})
    rows = [{"id": f"f{pid}", "setting": names.get(pid, str(pid)), "ok": r["ok"], "fails": r["fails"],
             "median_ms": round(r["median_ms"]), "past_wins": AI.fragment_wins(pid)}
            for pid, r in sorted(cands.items())]
    order, _reason = claude_rank_rows(CLAUDE_TUNE_SYSTEM, rows)
    for cid in order or []:
        try:
            pid = int(cid[1:])
        except ValueError:
            continue
        r = cands.get(pid)
        if r and r["fails"] <= best_fails and r["median_ms"] <= best_med * 1.25 + 30:
            return True, (pid or None)
    return decided, local


def ai_tune_dns_and_fragment(binary: str, last_tag: str, top_outbounds: list, all_outbounds: list,
                             manual_tag, fragment_preset):
    """After the AI Engine connected: choose the best DNS (UDP is tested first, TCP only when no
    provider answered over UDP) and the best Fragment preset with Gemini's help (local rules if
    there is no key / no answer), then apply both with ONE tunnel restart. If the tunnel does
    not pass the real proxy test with them, everything is put back.
    Returns (proc, last_tag, top_outbounds, all_outbounds, manual_tag, fragment_preset)."""
    global DNS_WINNER, DNS_DISABLED
    proc = _state.get("proc")
    unchanged = (proc, last_tag, top_outbounds, all_outbounds, manual_tag, fragment_preset)
    if not last_tag:
        return unchanged
    use_ai = claude_ready()

    # 1) DNS: UDP first, TCP only if UDP had no working provider.
    dns_results = []
    for proto in ("UDP", "TCP"):
        for _attempt in range(2):       # the tunnel was just rebuilt: give it a second chance
            try:
                dns_results = race_dns_results_via_tunnel(proto=proto)
            except Exception:
                dns_results = []
            if dns_results:
                break
            time.sleep(1.5)
        if dns_results:
            break
    new_dns = _ai_pick_dns(dns_results, use_ai) if dns_results else None

    # 2) Fragment, measured in isolation on the connected server.
    new_fragment, frag_decided = fragment_preset, False
    if _state.get("fragment_supported"):
        server = next((o for o in list(all_outbounds) + list(top_outbounds)
                       if o.get("tag") == last_tag), None)
        if server is not None:
            try:
                frag_decided, best_frag = _ai_pick_fragment(measure_fragment_results(binary, server), use_ai)
            except Exception:
                frag_decided, best_frag = False, None
            if frag_decided:
                new_fragment = best_frag

    if new_dns is None and new_fragment == fragment_preset:
        return unchanged

    # 3) Apply both at once.
    prev_dns, prev_dns_disabled, prev_fragment = DNS_WINNER, DNS_DISABLED, fragment_preset
    if new_dns is not None:
        DNS_WINNER, DNS_DISABLED = new_dns, False
    kill_singbox()
    _state["cleaned_up"] = False
    new_proc, new_tag, new_ok = connect_with_fallback(
        binary, top_outbounds, manual_tag, False, all_outbounds,
        show_info=False, enable_fragment=new_fragment, reset_options=False)
    if new_ok and new_tag:
        try:
            if new_dns is not None:
                AI.record_dns(new_dns)
            if frag_decided:
                AI.record_fragment(new_fragment)
        except Exception:
            pass
        return new_proc, new_tag, top_outbounds, all_outbounds, (new_tag if manual_tag else manual_tag), new_fragment

    # The line did not accept the new DNS / Fragment: restore the previous state.
    DNS_WINNER, DNS_DISABLED = prev_dns, prev_dns_disabled
    kill_singbox()
    _state["cleaned_up"] = False
    back_proc, back_tag, _back_ok = connect_with_fallback(
        binary, top_outbounds, manual_tag, False, all_outbounds,
        show_info=False, enable_fragment=prev_fragment, reset_options=False)
    return (back_proc if back_proc is not None else _state.get("proc"), back_tag or last_tag,
            top_outbounds, all_outbounds, (back_tag if (back_tag and manual_tag) else manual_tag),
            prev_fragment)


def ai_tune_run(binary: str, last_tag: str, top_outbounds: list, all_outbounds: list,
                manual_tag, fragment_preset):
    """ai_tune_dns_and_fragment() behind one visible spinner row; everything it prints is silenced."""
    who = "Gemini" if claude_ready() else "AI Engine"
    spinner = Spinner(f"AI Engine: {who} is choosing the best DNS + Fragment...", stream=sys.stdout)
    spinner.__enter__()
    try:
        with _silenced_stdout():
            return ai_tune_dns_and_fragment(binary, last_tag, top_outbounds, all_outbounds,
                                            manual_tag, fragment_preset)
    except Exception:
        return (_state.get("proc"), last_tag, top_outbounds, all_outbounds, manual_tag, fragment_preset)
    finally:
        spinner.__exit__(None, None, None)


def _auto_setting_run(binary: str, last_tag: str, top_outbounds: list, all_outbounds: list,
                       manual_tag, fragment_preset, full: bool = False, visible: bool = False):
    """Run one _auto_setting_cycle with everything it prints silenced, and note the time of
    the pass (the periodic 15-minute clock restarts from here).

    visible=True keeps a one-row spinner on the real terminal while it works - used when the
    screen is ours (right after the first connection, or after the user typed AS). The silent
    variant is for passes that start by themselves while the user may be typing at the prompt."""
    spinner = None
    if visible:
        spinner = Spinner("Auto Setting: finding the best Fragment + DNS...", stream=sys.stdout)
        spinner.__enter__()
    try:
        with _silenced_stdout():
            result = _auto_setting_cycle(binary, last_tag, top_outbounds, all_outbounds,
                                          manual_tag, fragment_preset, full=full)
    except Exception:
        result = (_state.get("proc"), last_tag, top_outbounds, all_outbounds, manual_tag, fragment_preset)
    finally:
        if spinner is not None:
            spinner.__exit__(None, None, None)
    _state["auto_setting_last_check"] = time.monotonic()
    if full and AUTO_SETTING_ENABLED and result[1]:
        # Auto Setting must leave DNS ON: if it could not be enabled yet (line busy, tunnel not
        # ready) the full pass is repeated a couple of times before giving up until the next cycle.
        if DNS_DISABLED or not DNS_WINNER:
            tries = int(_state.get("as_full_retries", 0)) + 1
            if tries <= 2:
                _state["as_full_retries"] = tries
                _state["as_full_pending"] = True
            else:
                _state["as_full_retries"] = 0
        else:
            _state["as_full_retries"] = 0
    return result


# ============================================================================
# First-run setup (Termux only)
# ============================================================================
# On the very first start in Termux this does, once:
#   1) pkg update + upgrade, and installs only what Ramin VPN needs (python, termux-api)
#   2) installs sing-box 1.14.1 (Termux repo if it offers exactly that version, otherwise the
#      official SagerNet android build, SHA-256 checked against GitHub's published digest)
#   3) creates the `Ramin` / `ramin` command that runs Ramin_VPN.py
# After that a marker file is written and none of it runs again. `Ramin --setup` repeats it.
SETUP_SINGBOX_VERSION = (1, 14, 1)
RAMIN_LAUNCH_PATH = "/storage/emulated/0/Download/Ramin_VPN/Ramin_VPN.py"
RAMIN_COMMAND_NAMES = ("Ramin", "ramin")
TERMUX_NEEDED_PACKAGES = ("python", "termux-api")   # nothing else is installed
SETUP_MARKER_PATH = os.path.join(os.path.expanduser("~"), ".ramin_vpn_setup.json")
_LAUNCHER_TAG = "# RAMIN_VPN_LAUNCHER"


def _is_termux() -> bool:
    return "com.termux" in os.environ.get("PREFIX", "") or os.path.isdir("/data/data/com.termux/files/usr")


def _termux_prefix() -> str:
    return os.environ.get("PREFIX") or "/data/data/com.termux/files/usr"


def _read_setup_state() -> dict:
    try:
        with open(SETUP_MARKER_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_setup_state(state: dict):
    try:
        state = dict(state, time=int(time.time()), singbox=".".join(map(str, SETUP_SINGBOX_VERSION)))
        with open(SETUP_MARKER_PATH, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except Exception:
        pass


def _setup_run(label: str, cmd: list, timeout: int = 1800) -> bool:
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    rc = 1
    with Spinner(label) as sp:
        try:
            rc = subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=timeout).returncode
        except Exception:
            rc = 1
        sp.failed = rc != 0
    if rc == 0:
        print(f"{OK} {label.rstrip('.')} - done")
    return rc == 0


def _termux_update_and_install() -> bool:
    """pkg update + upgrade, then ONLY the packages this program needs."""
    apt_opts = ["-y", "-o", "Dpkg::Options::=--force-confold"]
    ok_update = _setup_run("Refreshing package lists (pkg update)...", ["pkg", "update", "-y"])
    _setup_run("Upgrading installed packages (pkg upgrade)...", ["apt-get"] + apt_opts + ["upgrade"])
    ok_install = _setup_run(f"Installing required tools: {', '.join(TERMUX_NEEDED_PACKAGES)}...",
                            ["apt-get"] + apt_opts + ["install"] + list(TERMUX_NEEDED_PACKAGES))
    return ok_update and ok_install


def _singbox_acceptable(v) -> bool:
    """1.14.1 or a later 1.14.x patch. 1.14.0 and 1.15+ are replaced by the tested 1.14.1."""
    return bool(v) and v[0] == SETUP_SINGBOX_VERSION[0] and v[1] == SETUP_SINGBOX_VERSION[1] \
        and v[2] >= SETUP_SINGBOX_VERSION[2]


def _current_singbox():
    b = shutil.which("sing-box")
    return b, (get_singbox_version(b) if b else None)


def _apt_candidate_version(pkg_name: str):
    try:
        out = subprocess.run(["apt-cache", "policy", pkg_name], capture_output=True, text=True,
                             timeout=30).stdout
        m = re.search(r"Candidate:\s*(\S+)", out or "")
        return m.group(1) if m and m.group(1) != "(none)" else None
    except Exception:
        return None


def _install_binary_from_tarball(tar_path: str, dest_dir: str) -> str:
    """Extract ONLY the `sing-box` executable from the archive (nothing else is written, no
    archive path is trusted) into dest_dir and return its path."""
    import tarfile
    with tarfile.open(tar_path, "r:gz") as tf:
        member = next((m for m in tf.getmembers()
                       if m.isfile() and os.path.basename(m.name) == "sing-box"), None)
        if member is None:
            raise RuntimeError("the archive has no sing-box binary")
        src = tf.extractfile(member)
        dest = os.path.join(dest_dir, "sing-box")
        tmp_dest = dest + ".new"
        with open(tmp_dest, "wb") as out:
            shutil.copyfileobj(src, out)
    os.chmod(tmp_dest, 0o755)
    os.replace(tmp_dest, dest)
    return dest


def _download_official_singbox(version: tuple) -> bool:
    import hashlib
    import platform
    import tempfile
    ver = ".".join(map(str, version))
    tag = f"v{ver}"
    archs = {"aarch64": ["arm64"], "arm64": ["arm64"], "armv8l": ["arm", "armv7"],
             "armv7l": ["arm", "armv7"], "arm": ["arm", "armv7"], "x86_64": ["amd64"],
             "amd64": ["amd64"], "i686": ["386"], "i386": ["386"]}.get(platform.machine().lower())
    if not archs:
        print(f"{WARN} Unsupported CPU ({platform.machine()}): install sing-box {ver} manually.")
        return False

    digests = {}   # asset name -> "sha256:..." (GitHub publishes one for every release asset)
    try:
        req = urllib.request.Request(
            f"https://api.github.com/repos/SagerNet/sing-box/releases/tags/{tag}",
            headers={"User-Agent": "RaminVPN-Setup", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            for a in json.loads(resp.read().decode()).get("assets", []):
                digests[a.get("name", "")] = str(a.get("digest") or "")
    except Exception:
        pass

    bin_dir = os.path.join(_termux_prefix(), "bin")
    tmp_dir = tempfile.mkdtemp(prefix="ramin_sb_")
    try:
        for arch in archs:
            name = f"sing-box-{ver}-android-{arch}.tar.gz"
            if digests and name not in digests:
                continue   # GitHub answered and this asset does not exist
            url = f"https://github.com/SagerNet/sing-box/releases/download/{tag}/{name}"
            tar_path = os.path.join(tmp_dir, name)
            sha = hashlib.sha256()
            try:
                with Spinner(f"Downloading sing-box {ver} ({arch})...") as sp:
                    req = urllib.request.Request(url, headers={"User-Agent": "RaminVPN-Setup"})
                    with urllib.request.urlopen(req, timeout=60) as resp, open(tar_path, "wb") as f:
                        while True:
                            chunk = resp.read(1 << 16)
                            if not chunk:
                                break
                            f.write(chunk)
                            sha.update(chunk)
                    sp.failed = False
            except Exception as e:
                print(f"{WARN} Download failed ({name}): {e}")
                continue
            expected = digests.get(name, "")
            if expected.startswith("sha256:"):
                if sha.hexdigest() != expected.split(":", 1)[1].lower():
                    print(f"{FAIL} {name}: SHA-256 does not match GitHub's published digest - not installed.")
                    return False
                print(f"{OK} SHA-256 verified.")
            else:
                print(f"{WARN} Could not fetch GitHub's digest - the download could not be SHA-256 checked.")
            try:
                _install_binary_from_tarball(tar_path, bin_dir)
            except Exception as e:
                print(f"{WARN} Could not install sing-box: {e}")
                return False
            return True
        return False
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _ensure_singbox() -> bool:
    ver = ".".join(map(str, SETUP_SINGBOX_VERSION))
    _b, v = _current_singbox()
    if _singbox_acceptable(v):
        print(f"{OK} sing-box {'.'.join(map(str, v))} is already installed.")
        return True
    # 1) the Termux repo, but only when it offers exactly this version
    cand = _apt_candidate_version("sing-box")
    if cand and cand.startswith(ver):
        _setup_run(f"Installing sing-box {ver} (pkg)...",
                   ["apt-get", "-y", "-o", "Dpkg::Options::=--force-confold", "install", "sing-box"])
        _b, v = _current_singbox()
        if _singbox_acceptable(v):
            print(f"{OK} sing-box {'.'.join(map(str, v))} installed.")
            return True
    # 2) the official release build
    if _download_official_singbox(SETUP_SINGBOX_VERSION):
        _b, v = _current_singbox()
        if _singbox_acceptable(v):
            print(f"{OK} sing-box {'.'.join(map(str, v))} installed.")
            return True
        print(f"{WARN} sing-box was installed but did not report version {ver}.")
    else:
        print(f"{WARN} sing-box {ver} could not be installed automatically.")
    return False


def _resolve_launch_path() -> str:
    candidates = [RAMIN_LAUNCH_PATH]
    try:
        argv0 = os.path.abspath(sys.argv[0])
        if argv0.lower().endswith(".py"):
            candidates.append(argv0)
    except Exception:
        pass
    for c in candidates:
        if os.path.isfile(c):
            return c
    return RAMIN_LAUNCH_PATH


def _launcher_script(target: str) -> str:
    sh = os.path.join(_termux_prefix(), "bin", "sh")
    return (f"#!{sh}\n{_LAUNCHER_TAG}\n"
            f"SCRIPT={shlex.quote(target)}\n"
            'if [ ! -f "$SCRIPT" ]; then\n'
            '  echo "Ramin_VPN.py was not found: $SCRIPT"\n'
            '  echo "Run termux-setup-storage once and check that the file is in that folder."\n'
            "  exit 1\n"
            "fi\n"
            # the program keeps its data files in the current directory: always the program's folder
            'cd "$(dirname "$SCRIPT")" || exit 1\n'
            'exec python "$SCRIPT" "$@"\n')


def _ensure_launchers(quiet: bool = True) -> bool:
    """Create/refresh the `Ramin` and `ramin` commands (files in $PREFIX/bin). Only files
    created by this program are ever overwritten."""
    target = _resolve_launch_path()
    content = _launcher_script(target)
    bin_dir = os.path.join(_termux_prefix(), "bin")
    ok = True
    for name in RAMIN_COMMAND_NAMES:
        path = os.path.join(bin_dir, name)
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    current = f.read()
                if current == content:
                    continue
                if _LAUNCHER_TAG not in current:
                    if not quiet:
                        print(f"{WARN} {path} already exists and is not ours - left untouched.")
                    ok = False
                    continue
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            os.chmod(path, 0o755)
        except Exception as e:
            ok = False
            if not quiet:
                print(f"{WARN} Could not create the '{name}' command: {e}")
    if ok and not quiet:
        print(f"{OK} Command created: type  Ramin  in Termux to start ({target})")
    return ok


def first_run_setup(force: bool = False):
    """See the block comment above. Never raises: a failed setup must not stop the program."""
    if not _is_termux():
        return
    try:
        reexec = os.environ.pop("RAMIN_SETUP_REEXEC", None) == "1"
        state = {} if (force and not reexec) else _read_setup_state()
        if state.get("done"):
            _ensure_launchers(quiet=True)   # cheap self-heal, no network
            return

        if not reexec and not state.get("packages_done"):
            print(f"\n{INFO} First-time setup for Termux - this runs only once.\n")
            state["packages_done"] = _termux_update_and_install()
            _save_setup_state(state)
            # Continue in a fresh interpreter: python itself may just have been upgraded.
            os.environ["RAMIN_SETUP_REEXEC"] = "1"
            sys.stdout.flush()
            try:
                os.execv(sys.executable, [sys.executable] + sys.argv)
            except Exception:
                os.environ.pop("RAMIN_SETUP_REEXEC", None)

        singbox_ok = _ensure_singbox()
        _ensure_launchers(quiet=False)
        if singbox_ok:
            state["done"] = True
            _save_setup_state(state)
            print(f"{OK} Setup finished. Next time just type:  Ramin\n")
        else:
            _save_setup_state(state)
            print(f"{WARN} Setup is not complete (no internet?). It will try again next start.\n")
    except KeyboardInterrupt:
        print(f"\n{WARN} Setup interrupted - it will run again next start.")
        sys.exit(0)
    except Exception as e:
        print(f"{WARN} Setup skipped: {e}")


def main():
    global SPEED_BOOST_ENABLED, SPEED_BOOST2_ENABLED, FAST_CONNECT_ENABLED, AUTO_SETTING_ENABLED
    print_banner()
    first_run_setup(force=("--setup" in sys.argv))
    cleanup_stale_verify_configs()   # leftover singbox-config.json.fvone./.frag. files from a
                                      # previous run that was killed mid-test (nothing from
                                      # THIS run's own testing can exist yet)
    install_cleanup_handlers()
    acquire_wake_lock()
    start_stdin_reader()

    binary = find_singbox_binary()
    if not binary:
        print_install_instructions()
        sys.exit(1)

    singbox_version = get_singbox_version(binary)
    if singbox_version is None or singbox_version < REQUIRED_SINGBOX_VERSION:
        shown = ".".join(map(str, singbox_version)) if singbox_version else "unknown"
        print(f"{WARN} sing-box {shown} is too old for this script.")
        print(f"{INFO} Required: sing-box >= {'.'.join(map(str, REQUIRED_SINGBOX_VERSION))}.")
        print(f"{INFO} Update sing-box first (Termux: pkg upgrade sing-box, or download 1.14.x from")
        print(f"{INFO} https://github.com/SagerNet/sing-box/releases), then run this script again.")
        sys.exit(1)
    fragment_supported = singbox_version >= FRAGMENT_MIN_VERSION
    _state["fragment_supported"] = fragment_supported
    _init_reserve(binary)  # silent Free Vless reserve (see FV_RESERVE_* constants)

    # A single numbered pipeline covers the whole connection process, so
    # every status line says "<Name> i/N" (e.g. "TCP 4/10", "DNS 10/10")
    # instead of a generic "Stage" - and internal plumbing details (wake
    # lock, port probing, killing/restarting sing-box between phases,
    # per-DNS-provider checks) stay folded inside these steps instead of
    # printing their own lines.
    steps = StepCounter(["Ports", "Fetch", "Find", "TCP", "TLS", "Verify", "Geo", "Connect"])

    print_transient(f"{INFO} {steps.next()}")  # Ports
    original_port_count = len(EXTRA_PORTS)
    working_extra = probe_bindable_ports(EXTRA_PORTS, verbose=True)
    EXTRA_PORTS[:] = working_extra  # mutate in place: build_singbox_config() and
    # the later print statements all read this same global list
    if not working_extra:
        print(f"{WARN} None of the extra ports could be opened - only the main port will be active.")
    else:
        print(f"{OK} {len(working_extra)}/{original_port_count} extra ports opened.")

    fast_connected = False
    ir_bypass_enabled = False
    reset_optional_settings_for_connection()
    fast_state = load_fast_connect_state()
    if FAST_CONNECT_ENABLED and fast_state.get("outbound") and fast_state.get("tag"):
        print(f"{OK} Fast Connect: trying the last successful {fast_state.get('tag')} first...")
        fast_ob = fast_state.get("outbound")
        fast_tag = fast_state.get("tag")
        _state["free_vless_mode"] = bool(fast_state.get("free_vless_mode", False)) or tag_is_free_source(fast_tag)
        if _state["free_vless_mode"]:
            _state["free_source_index"] = fast_state.get("free_source_index")
        try:
            kill_singbox()
            _state["cleaned_up"] = False
            proc, last_tag, ok = connect_with_fallback(
                binary, [fast_ob], fast_tag, False, [fast_ob],
                label="Fast Connect", show_info=False, enable_fragment=None
            )
            if ok and last_tag:
                all_outbounds = [fast_ob]
                cached_pool = []
                if _state.get("free_vless_mode"):
                    # Prefer the pool persisted with Fast Connect. If an older
                    # fast_connect.json has no pool, use the switch-server cache;
                    # if that is missing/too small, rebuild the last verified FV
                    # pool from free_vless_cache.json.
                    saved_pool = fast_state.get("free_pool")
                    if isinstance(saved_pool, list) and len(saved_pool) >= 2:
                        cached_pool = saved_pool[:FREE_VLESS_COUNT]
                    else:
                        cached_pool = load_switch_server_pool(switch_server_cache_key(True, fast_state.get("free_source_index")))
                    if len(cached_pool) < 2:
                        rebuilt = rebuild_free_pool_from_saved_lines(fast_state.get("free_source_index"))
                        if len(rebuilt) >= 2:
                            cached_pool = rebuilt
                            save_switch_server_pool(switch_server_cache_key(True, fast_state.get("free_source_index")), rebuilt)
                    _state["free_verified_pool"] = cached_pool[:FREE_VLESS_COUNT]
                else:
                    m0 = re.match(r"^S(\d+)-", str(fast_tag))
                    if m0:
                        cached_pool = load_switch_server_pool(f"SUB:{int(m0.group(1)) - 1}")
                top_outbounds = list(cached_pool or [fast_ob])
                # The saved/rebuilt pool may not contain the server Fast Connect
                # just connected to. Then the panel could not find it in the list
                # and showed "Connected ? server" / "Protocol : ?" with no Address
                # line. Always keep the connected server in the pool (as #1).
                if not any(o.get("tag") == last_tag for o in top_outbounds):
                    top_outbounds.insert(0, fast_ob)
                if _state.get("free_vless_mode"):
                    _state["free_verified_pool"] = top_outbounds[:FREE_VLESS_COUNT]
                all_outbounds = top_outbounds
                manual_tag = last_tag
                _state["current_sub_index"] = None
                if str(last_tag).startswith("S"):
                    m = re.match(r"^S(\d+)-", str(last_tag))
                    if m:
                        idx0 = int(m.group(1)) - 1
                        if 0 <= idx0 < len(SUB_URLS):
                            _state["current_sub_index"] = idx0
                fast_connected = True
                if _state.get("free_vless_mode") and _RESERVE is not None:
                    # A protocol-feed server (PX-...): keep looking for the SAME protocol in the background.
                    if str(last_tag).startswith("PX-") and not _RESERVE.protocol:
                        ptype = str(fast_ob.get("type") or "")
                        if ptype and _protocol_match(fast_ob, ptype):
                            _RESERVE.set_binding(protocol=ptype, protocol_name=protocol_label(fast_ob) or ptype)
                    elif str(last_tag).startswith("FV-") and _RESERVE.protocol:
                        _RESERVE.set_binding()
                    save_fast_connect_state(last_tag, fast_ob, True, _state.get("free_source_index"))
                print(f"{OK} Fast Connect succeeded: {last_tag}")
            else:
                print(f"{WARN} Fast Connect failed - starting Free Vless automatically.")
                _state["free_vless_mode"] = False
        except Exception as e:
            print(f"{WARN} Fast Connect failed ({e}) - starting Free Vless automatically.")
            _state["free_vless_mode"] = False

    if (not fast_connected and _RESERVE is not None and FAST_CONNECT_ENABLED
            and fast_state.get("free_vless_mode") and _RESERVE.count() > 0):
        # The last Free Vless node is gone, but the reserve found earlier may still work.
        try:
            res = reserve_failover(binary, _RESERVE, show_info=False, label="Fast Connect")
        except Exception:
            res = None
        if res:
            proc, last_tag, ok, top_outbounds, manual_tag = res
            all_outbounds = top_outbounds
            _state["free_vless_mode"] = True
            _state["current_sub_index"] = None
            fast_connected = True
            print(f"{OK} Fast Connect succeeded from the saved reserve: {last_tag}")

    # Every startup connection is intentionally RAW. No automatic DNS,
    # Fragment, Speed Boost, or Iran-bypass layer is added here.
    # ChatGPT/OpenAI is still routed through the active tunnel by the base
    # OpenAI route rules in build_singbox_config(). Optional features can be
    # enabled manually after the tunnel is up.
    global DNS_WINNER, DNS_DISABLED
    if not fast_connected:
        reset_optional_settings_for_connection()
    ir_bypass_enabled = False
    fragment_preset = None

    used_t_fallback = False
    if not fast_connected:
        # The program always starts in Free Vless (FV) mode: T1 first, then the other sources.
        _release_country_binding()
        _state["free_vless_mode"] = True
        print_transient(f"{INFO} Starting Free Vless (FV)...")
        fv_proc, last_tag, ok, fv_top, fv_manual, fv_idx = connect_free_vless_with_failover(
            binary, ir_bypass_enabled=False, first_source_index=0, enable_fragment=None)
        if last_tag and ok and fv_top:
            proc = fv_proc
            top_outbounds = all_outbounds = fv_top
            manual_tag = fv_manual or last_tag
            _state["free_vless_mode"] = True
            used_t_fallback = True
            print(f"{OK} Free Vless connected from {get_free_vless_source_name(fv_idx)}.")
        else:
            # Nothing connected yet: stay in FV mode; the main loop keeps retrying the FV chain.
            _state["free_vless_mode"] = True
            last_tag, ok, manual_tag = None, False, None
            top_outbounds, all_outbounds = [], []
            proc = _FvRetryProcess(RETRY_BACKOFF_SECONDS[0])
            print(f"{WARN} No Free Vless source produced a live connection - retrying automatically.")

        if last_tag and ok:
            print_transient(f"{OK} Config saved: {CONFIG_PATH}")
            print_transient(f"{OK} Manually pinned to: {manual_tag}" if manual_tag
                             else f"{OK} Auto-picks the best of the top {TOP_N}.")
            fragment_hint = ", 'f1'-'f4' + Enter to try a Fragment preset" if fragment_supported else ""
            print_transient(f"{OK} Type 'r' + Enter to rescan, 'b' + Enter Speed Boost, 'b2' + Enter Speed Boost 2, "
                  f"a number (1-{len(top_outbounds)}) + Enter to switch server{fragment_hint}, "
                  f"'d1'-'d{len(DNS_PROVIDERS)}' + Enter to pick a DNS provider, "
                  f"'fv' + Enter for Free VLESS.")

    clear_line()

    # Startup is normally S1..Sx; keep Fast Connect's saved FV state if it was used, and keep
    # free_vless_mode ON if the S-sub totally failed and a T<n> source connected instead.
    if not fast_connected and not used_t_fallback:
        _state["free_vless_mode"] = True   # FV mode; the main loop retries if nothing connected

    # Final result - the box is shown exactly once here, then the pulsing
    # CONNECT line takes over in the monitoring loop below.
    if last_tag:
        render_connection_status(last_tag, all_outbounds, top_outbounds, label="Connected VLESS server",
                                  fragment_preset=fragment_preset)
        send_notification("VLESS متصل شد" if ok else "VLESS با مشکل متصل شد", last_tag)
        if ok:
            # First connection ever: ask (once, until answered) whether to enable Auto Setting.
            prompt_auto_setting_first_run(last_tag, all_outbounds)
            if AUTO_SETTING_ENABLED and _state.get("as_full_pending"):
                # Auto Setting is ON - just answered Y, or kept from an earlier run: this fresh
                # connection's best Fragment + best DNS pick is scheduled for
                # AUTO_SETTING_FULL_DELAY_SECONDS from now (see the main loop below),
                # not run immediately here.
                _state["as_full_pending_since"] = time.monotonic()
            render_connection_status(last_tag, all_outbounds, top_outbounds, label="Connected VLESS server",
                                      fragment_preset=fragment_preset)
    else:
        print(f"{WARN} Could not establish a working connection.")

    retry_count = 0
    elapsed_since_monitor = 0

    try:
        while True:
            # Auto Setting ON + a fresh connection: pick the best DNS and Fragment RIGHT NOW,
            # before the prompt is shown (the screen was drawn without "Type + Enter"). The
            # prompt only comes back once this is finished.
            if AUTO_SETTING_ENABLED and last_tag and proc and proc.poll() is None \
                    and _state.get("as_full_pending"):
                for _as_pass in range(4):  # a pass may repeat itself (line busy) - bounded
                    if not (AUTO_SETTING_ENABLED and last_tag and proc and proc.poll() is None
                            and _state.get("as_full_pending")):
                        break
                    _state.pop("as_visible_next", None)
                    (proc, last_tag, top_outbounds, all_outbounds, manual_tag,
                     fragment_preset) = _auto_setting_run(
                        binary, last_tag, top_outbounds, all_outbounds, manual_tag, fragment_preset,
                        full=True, visible=True)
                    _state["as_full_pending_since"] = None
                _state["as_full_pending"] = False  # never leave the prompt hidden
                if last_tag:
                    render_connection_status(last_tag, all_outbounds, top_outbounds,
                                              label="Connected VLESS server",
                                              fragment_preset=fragment_preset)
            line = wait_with_pulse(input_queue, CHECK_INTERVAL_SECONDS)
            elapsed_since_monitor += CHECK_INTERVAL_SECONDS

            # Auto Setting, while the user is idle (a typed command is always handled first):
            # a FRESH connection (as_full_pending: server / source / subscription changed, the
            # tunnel was rebuilt raw) gets its best Fragment + best DNS picked once, but only
            # AUTO_SETTING_FULL_DELAY_SECONDS (3 min) after it connects, not the instant it comes
            # up - and nothing periodic runs after that; the next full pass only comes from the
            # next fresh connection. Fully silent: nothing may be printed under the prompt; the
            # panel is redrawn if anything on it changed.
            if AUTO_SETTING_ENABLED and last_tag and proc and proc.poll() is None and not line:
                if _state.get("as_full_pending") and not _state.get("as_full_pending_since"):
                    _state["as_full_pending_since"] = time.monotonic()
                _as_ready = bool(_state.get("as_full_pending")) and (
                    time.monotonic() - _state.get("as_full_pending_since", 0)
                    >= AUTO_SETTING_FULL_DELAY_SECONDS)
                if _as_ready:
                    _sig_before = _auto_setting_signature(last_tag, proc, fragment_preset)
                    _vis = bool(_state.pop("as_visible_next", False))
                    if _vis:
                        print()  # a row of its own for the spinner, below the prompt
                    (proc, last_tag, top_outbounds, all_outbounds, manual_tag,
                     fragment_preset) = _auto_setting_run(
                        binary, last_tag, top_outbounds, all_outbounds, manual_tag, fragment_preset,
                        full=True, visible=_vis)
                    _state["as_full_pending_since"] = None
                    if last_tag and _auto_setting_signature(last_tag, proc, fragment_preset) != _sig_before:
                        render_connection_status(last_tag, all_outbounds, top_outbounds,
                                                  label="Connected VLESS server",
                                                  fragment_preset=fragment_preset)

            _site_files_cleanup()   # deletes data/site_*.txt older than 5 days (at most once an hour)
            if time.time() - _state.get("verify_cfg_cleanup_at", 0.0) >= _VERIFY_CONFIG_CLEANUP_EVERY:
                _state["verify_cfg_cleanup_at"] = time.time()
                cleanup_stale_verify_configs(min_age_seconds=_VERIFY_CONFIG_MAX_AGE_SECONDS)
            if _RESERVE is not None:
                try:
                    _RESERVE.tick(bool(last_tag) and proc.poll() is None)
                    if last_tag and _state.get("free_vless_mode"):
                        top_outbounds, all_outbounds = _merge_reserve_into_pool(top_outbounds, all_outbounds)
                    # The reserve just became full: redraw once so Switch Server
                    # shows the new range (1-N) and the user sees the healthy configs.
                    if (_RESERVE.consume_full_refresh() and not line and last_tag
                            and _state.get("free_vless_mode") and proc.poll() is None):
                        render_connection_status(last_tag, all_outbounds, top_outbounds,
                                                  label="Connected VLESS server",
                                                  fragment_preset=fragment_preset, reuse_info=True)
                except Exception:
                    pass

            if line and line.strip().lower() in RESCAN_COMMANDS:
                disable_speed_and_fragment()
                fragment_preset = None
                if True:  # R always uses the Free Vless chain (S1-S8 were removed)
                    print(f"\n{OK} Free Vless R: disconnecting current VPN and moving through the FV-only source chain...")
                    kill_singbox()
                    _state["cleaned_up"] = False
                    (proc, last_tag, ok, new_top_outbounds, new_manual_tag,
                     free_source_index) = connect_free_vless_with_failover(
                        binary, ir_bypass_enabled=False, first_source_index=None,
                        enable_fragment=None
                    )
                    if last_tag and ok and new_top_outbounds:
                        all_outbounds = new_top_outbounds
                        top_outbounds = new_top_outbounds
                        manual_tag = new_manual_tag or last_tag
                        _state["free_vless_mode"] = True
                        retry_count = 0
                        source_name = get_free_vless_source_name(free_source_index)
                        print(f"{OK} Free Vless R connected from {source_name}: {last_tag}")
                        send_notification("Free Vless دوباره وصل شد", last_tag)
                        render_connection_status(last_tag, all_outbounds, top_outbounds,
                                                  label="Connected Free Vless", fragment_preset=fragment_preset)
                    else:
                        _state["free_vless_mode"] = True
                        all_outbounds = []
                        top_outbounds = []
                        manual_tag = None
                        last_tag = None
                        print(f"{WARN} Free Vless R: this FV cycle produced no live connection. S1-S8 remain excluded.")
                        wait_s = RETRY_BACKOFF_SECONDS[min(retry_count, len(RETRY_BACKOFF_SECONDS) - 1)]
                        retry_count = min(retry_count + 1, len(RETRY_BACKOFF_SECONDS) - 1)
                        proc = _FvRetryProcess(wait_s)
                    elapsed_since_monitor = 0
                    continue

            cmd = line.strip().lower() if line else ""

            if cmd in SPEED_BOOST_COMMANDS or cmd in SPEED_BOOST2_COMMANDS:
                is_boost2 = cmd in SPEED_BOOST2_COMMANDS

                if is_boost2:
                    new_state = not SPEED_BOOST2_ENABLED
                    print(f"\n{OK} Speed Boost 2 {'ON' if new_state else 'OFF'} - reconnecting with the aggressive transport settings...")
                    SPEED_BOOST2_ENABLED = new_state
                    if new_state:
                        SPEED_BOOST_ENABLED = False
                else:
                    new_state = not SPEED_BOOST_ENABLED
                    print(f"\n{OK} Speed Boost {'ON' if new_state else 'OFF'} - reconnecting with the transport settings...")
                    SPEED_BOOST_ENABLED = new_state
                    if new_state:
                        SPEED_BOOST2_ENABLED = False

                kill_singbox()
                _state["cleaned_up"] = False

                new_proc, new_tag, new_ok = connect_with_fallback(
                    binary, top_outbounds, manual_tag, False,
                    all_outbounds, label="Reconnected", enable_fragment=None, reset_options=False
                )

                # Fail safe: if the selected boost breaks the real exit-IP
                # check, disable it and reconnect in plain mode.
                if new_state and not new_ok:
                    if is_boost2:
                        print(f"{WARN} Speed Boost 2 did not pass the connection check on this node - reverting to OFF.")
                        SPEED_BOOST2_ENABLED = False
                    else:
                        print(f"{WARN} Speed Boost did not pass the connection check on this node - reverting to OFF.")
                        SPEED_BOOST_ENABLED = False

                    kill_singbox()
                    _state["cleaned_up"] = False
                    new_proc, new_tag, new_ok = connect_with_fallback(
                        binary, top_outbounds, manual_tag, ir_bypass_enabled,
                        all_outbounds, label="Reconnected", enable_fragment=None
                    )

                proc, last_tag, ok = new_proc, new_tag, new_ok
                if manual_tag and last_tag and last_tag != manual_tag:
                    manual_tag = last_tag

                if last_tag:
                    if SPEED_BOOST2_ENABLED:
                        notice = "Speed Boost 2 ON"
                    elif SPEED_BOOST_ENABLED:
                        notice = "Speed Boost ON"
                    else:
                        notice = "Speed Boost OFF"
                    send_notification(notice, last_tag)
                    render_connection_status(last_tag, all_outbounds, top_outbounds,
                                              label="Reconnected", fragment_preset=fragment_preset)

                retry_count = 0
                elapsed_since_monitor = 0
                continue

            if cmd in FRAGMENT_PRESET_COMMANDS or cmd in FRAGMENT_TOGGLE_COMMANDS:
                if not fragment_supported:
                    print(f"\n{WARN} This sing-box build (needs 1.13.0+) doesn't support Fragment - skipping.")
                elif cmd in FRAGMENT_TOGGLE_COMMANDS:
                    if fragment_preset:
                        print(f"\n{OK} Disabling Fragment...")
                        fragment_preset = None
                        kill_singbox()
                        _state["cleaned_up"] = False
                        proc, last_tag, ok = connect_with_fallback(
                            binary, top_outbounds, manual_tag, False,
                            all_outbounds, label="Reconnected", enable_fragment=None, reset_options=False
                        )
                    else:
                        print(f"\n{WARN} Fragment is off - use 'f1'-'f4' to pick a preset to try.")
                        continue
                else:
                    preset_id = FRAGMENT_PRESET_COMMANDS[cmd]
                    preset_name = FRAGMENT_PRESETS[preset_id]["name"]
                    print(f"\n{OK} Trying Fragment preset {preset_id} ({preset_name})...")
                    kill_singbox()
                    _state["cleaned_up"] = False
                    new_proc, new_tag, new_ok = connect_with_fallback(
                        binary, top_outbounds, manual_tag, False,
                        all_outbounds, label="Reconnected", enable_fragment=preset_id, reset_options=False
                    )
                    if new_ok:
                        proc, last_tag, ok = new_proc, new_tag, new_ok
                        fragment_preset = preset_id
                        if manual_tag and last_tag and last_tag != manual_tag:
                            manual_tag = last_tag
                    else:
                        print(f"{WARN} Preset {preset_id} ({preset_name}) failed the exit-IP check - "
                              f"reverting to no Fragment.")
                        fragment_preset = None
                        kill_singbox()
                        _state["cleaned_up"] = False
                        proc, last_tag, ok = connect_with_fallback(
                            binary, top_outbounds, manual_tag, ir_bypass_enabled,
                            all_outbounds, label="Reconnected", enable_fragment=None
                        )
                if manual_tag and last_tag and last_tag != manual_tag:
                    manual_tag = last_tag
                if last_tag:
                    send_notification("VLESS دوباره وصل شد" if ok else "VLESS با مشکل وصل شد", last_tag)
                retry_count = 0
                elapsed_since_monitor = 0
                continue

            if cmd in DNS_ALL_TEST_COMMANDS or cmd in DNS_ALL_TEST_UDP_COMMANDS or cmd in DNS_ALL_TEST_TCP_COMMANDS:
                proto_only = "UDP" if cmd in DNS_ALL_TEST_UDP_COMMANDS else ("TCP" if cmd in DNS_ALL_TEST_TCP_COMMANDS else None)
                what = f"every DNS provider ({proto_only} only)" if proto_only else "every DNS provider (UDP + TCP)"
                print(f"\n{OK} Test All: testing {what} through the current raw tunnel...")
                with Spinner(f"Testing all DNS providers{f' ({proto_only})' if proto_only else ''}...") as sp:
                    winner = race_dns_via_tunnel(proto=proto_only)
                    sp.failed = winner is None
                if winner:
                    DNS_WINNER = winner
                    DNS_DISABLED = False
                    print(f"{OK} Best DNS: {winner['name']} {winner['ip']} ({winner['proto']}, {winner['latency_ms']:.0f} ms)")
                    kill_singbox()
                    _state["cleaned_up"] = False
                    proc, last_tag, ok = connect_with_fallback(
                        binary, top_outbounds, manual_tag, False, all_outbounds,
                        label="Reconnected", enable_fragment=None, reset_options=False
                    )
                    if manual_tag and last_tag and last_tag != manual_tag:
                        manual_tag = last_tag
                else:
                    DNS_WINNER = None
                    DNS_DISABLED = True
                    print(f"{WARN} Test All: no DNS provider answered{f' over {proto_only}' if proto_only else ''} - DNS remains OFF.")
                retry_count = 0
                elapsed_since_monitor = 0
                if last_tag:
                    render_connection_status(last_tag, all_outbounds, top_outbounds,
                                              label="Reconnected", fragment_preset=None)
                continue

            if cmd in DNS_PROVIDER_COMMANDS or cmd in DNS_OFF_COMMANDS:
                if cmd in DNS_OFF_COMMANDS:
                    print(f"\n{OK} Disabling tunnel DNS (using system default)...")
                    DNS_DISABLED = True
                else:
                    idx = DNS_PROVIDER_COMMANDS[cmd]
                    provider_name = DNS_PROVIDERS[idx][0]
                    print(f"\n{OK} Trying DNS provider {provider_name}...")
                    with Spinner(f"Testing {provider_name} (and fallbacks) through the tunnel...") as sp:
                        winner = pick_dns_via_tunnel(start_index=idx)
                        sp.failed = winner is None
                    if winner:
                        DNS_WINNER = winner
                        DNS_DISABLED = False
                        if winner["name"] != provider_name:
                            print(f"{WARN} {provider_name} didn't answer - using {winner['name']} instead.")
                    else:
                        print(f"{WARN} Every DNS provider failed - falling back to system default.")
                        DNS_DISABLED = True
                kill_singbox()
                _state["cleaned_up"] = False
                proc, last_tag, ok = connect_with_fallback(
                    binary, top_outbounds, manual_tag, False,
                    all_outbounds, label="Reconnected", enable_fragment=None, reset_options=False
                )
                if manual_tag and last_tag and last_tag != manual_tag:
                    manual_tag = last_tag
                if last_tag:
                    send_notification("VLESS دوباره وصل شد" if ok else "VLESS با مشکل وصل شد", last_tag)
                retry_count = 0
                elapsed_since_monitor = 0
                continue

            if cmd in AI_COMMANDS:
                # AI Engine: one-shot. Speed-test, rank with learned knowledge,
                # connect to the best, then it is done (nothing stays active).
                UB.mark_ai_run()
                _ub_line = UB.summary_line()
                if _ub_line:
                    print(f"\n{INFO} AI Engine: {_ub_line}")
                disable_speed_and_fragment()
                fragment_preset = None
                if not claude_ready():
                    prompt_claude_key()   # box + "Gemini API key :" - saved to Jason/gemini_api_key.txt
                print(f"\n{INFO} AI Engine: testing candidates ({AI_ENGINE_BUDGET:.0f}s max)"
                      f"{' + Gemini review' if claude_ready() else ' (no Gemini key - local AI only)'}...")
                _snap = _snapshot_connection(proc, last_tag, all_outbounds, top_outbounds, manual_tag)
                status, data = connect_by_ai(binary)
                if status == "ok":
                    proc, last_tag, ok, top_outbounds, manual_tag, _src = data
                    all_outbounds = top_outbounds
                    _state["free_vless_mode"] = True
                    retry_count = 0
                    if ok:
                        # 1) best DNS (UDP first, then TCP) + best Fragment, chosen with Gemini;
                        # 2) then a silent ~2-minute sweep of the other sources fills Switch Server.
                        (proc, last_tag, top_outbounds, all_outbounds, manual_tag,
                         fragment_preset) = ai_tune_run(
                            binary, last_tag, top_outbounds, all_outbounds, manual_tag, fragment_preset)
                        _state["as_full_pending"] = False   # DNS + Fragment were just chosen above
                        _state.pop("as_visible_next", None)
                        if _RESERVE is not None and last_tag:
                            _RESERVE.start_ai_scan()
                    _state["ai_tag"] = last_tag
                    send_notification("AI Engine", last_tag)
                    render_connection_status(last_tag, all_outbounds, top_outbounds,
                                              label="Connected AI", fragment_preset=fragment_preset)
                else:
                    (proc, last_tag, all_outbounds, top_outbounds,
                     manual_tag) = _restore_previous_connection(
                        binary, ir_bypass_enabled, fragment_preset, _snap)
                    print(f"{_C.YELLOW}{NO_RESULTS_MESSAGE}{_C.RESET}", flush=True)
                    time.sleep(NO_RESULTS_DISPLAY_SECONDS)
                    if last_tag:
                        render_connection_status(last_tag, all_outbounds, top_outbounds,
                                                  label="Connected VLESS server", fragment_preset=fragment_preset)
                elapsed_since_monitor = 0
                continue

            if cmd in FREE_VLESS_COMMANDS:
                # FV is an isolated pool. Speed Boost/Fragment are reset silently.
                disable_speed_and_fragment()
                fragment_preset = None
                if _RESERVE is not None:
                    _RESERVE.set_country(None)  # plain FV = any country
                if _RESERVE is not None and _RESERVE.count() > 0:
                    # Healthy configs were already found in the background: use
                    # them instead of searching again (the old connection stays
                    # up while they are re-tested).
                    res = reserve_failover(binary, _RESERVE, label="Connected Free Vless")
                    if res:
                        proc, last_tag, ok, top_outbounds, manual_tag = res
                        all_outbounds = top_outbounds
                        retry_count = 0
                        send_notification("Free Vless متصل شد", last_tag)
                        elapsed_since_monitor = 0
                        continue
                kill_singbox()
                _state["cleaned_up"] = False

                (proc, last_tag, ok, new_top_outbounds, new_manual_tag,
                 free_source_index) = connect_free_vless_with_failover(
                    binary, ir_bypass_enabled=False, first_source_index=0,
                    enable_fragment=None
                )

                if last_tag and ok and new_top_outbounds:
                    _state["free_vless_mode"] = True
                    all_outbounds = new_top_outbounds
                    top_outbounds = new_top_outbounds
                    manual_tag = new_manual_tag or last_tag
                    retry_count = 0
                    source_name = get_free_vless_source_name(free_source_index)
                    print(f"{OK} Free Vless connected from {source_name}: {last_tag}")
                    send_notification("Free Vless متصل شد", last_tag)
                    render_connection_status(last_tag, all_outbounds, top_outbounds,
                                              label="Connected Free Vless", fragment_preset=fragment_preset)
                else:
                    # Stay in FV mode so the monitor can retry the FV-only
                    # chain later. Never restore or consult S1-S8 here.
                    _state["free_vless_mode"] = True
                    all_outbounds = []
                    top_outbounds = []
                    manual_tag = None
                    last_tag = None
                    print(f"{WARN} Every Free Vless source failed. No S1-S8 fallback will be used; the FV chain will retry later.")
                    wait_s = RETRY_BACKOFF_SECONDS[min(retry_count, len(RETRY_BACKOFF_SECONDS) - 1)]
                    retry_count = min(retry_count + 1, len(RETRY_BACKOFF_SECONDS) - 1)
                    proc = _FvRetryProcess(wait_s)

                elapsed_since_monitor = 0
                continue

            if cmd in FV_SOURCE_COMMANDS:
                # T1..Tn: search exactly that Free Vless source and connect to the
                # FIRST healthy server found. The current connection stays up while
                # searching (tests run on the normal internet) and is replaced only
                # when a healthy server is found.
                src = FV_SOURCE_COMMANDS[cmd]
                UB.record_search(source=f"T{src + 1}")
                disable_speed_and_fragment()
                fragment_preset = None
                _state["fv_quality_level"] = None
                new_top, new_manual = discover_free_vless(binary, source_index=src, verbose=True,
                                                          ping_ceiling_ms=800)
                if new_top:
                    kill_singbox()
                    _state["cleaned_up"] = False
                    _state["free_vless_mode"] = True  # the screen is drawn inside connect_with_fallback()
                    _state["free_source_index"] = src
                    _state["free_verified_pool"] = new_top[:FREE_VLESS_COUNT]
                    np, nt, nok = connect_with_fallback(
                        binary, new_top, new_manual, False, new_top,
                        label="Connected Free Vless", enable_fragment=None
                    )
                    if nt and nok:
                        proc, last_tag, ok = np, nt, nok
                        _state["free_vless_mode"] = True
                        _state["free_source_index"] = src
                        _state["free_verified_pool"] = new_top[:FREE_VLESS_COUNT]
                        all_outbounds = new_top
                        top_outbounds = new_top
                        manual_tag = new_manual or nt
                        retry_count = 0
                        save_switch_server_pool(switch_server_cache_key(True, src), new_top)
                        if _RESERVE is not None:
                            _RESERVE.set_country(None)  # any country again ...
                            _RESERVE.clear()  # ... and extra servers will now come from this source
                            _RESERVE.set_ping_ceiling(800)  # background fill prefers sub-800ms servers too
                        send_notification("Free Vless متصل شد", last_tag)
                    else:
                        # The old connection was already replaced and the new one failed:
                        # stay in FV mode and let the monitor retry (same as the FV command).
                        kill_singbox()
                        _state["cleaned_up"] = False
                        _state["free_vless_mode"] = True
                        all_outbounds, top_outbounds = [], []
                        manual_tag, last_tag = None, None
                        print(f"{WARN} Source T{src + 1} found servers but none could connect; the FV chain will retry later.")
                        wait_s = RETRY_BACKOFF_SECONDS[min(retry_count, len(RETRY_BACKOFF_SECONDS) - 1)]
                        retry_count = min(retry_count + 1, len(RETRY_BACKOFF_SECONDS) - 1)
                        proc = _FvRetryProcess(wait_s)
                else:
                    print(f"\n{WARN} Source T{src + 1} had no healthy server - keeping the current connection.")
                    _countdown_then_refresh(3, last_tag, all_outbounds, top_outbounds,
                                             fragment_preset=fragment_preset,
                                             label="Connected VLESS server")
                elapsed_since_monitor = 0
                continue

            if cmd in SWITCH_SUB_COMMANDS:
                # Smart sequential source switch: FV skips Barry-Far Sub1..Sub5
                # and starts at fallback source F1; normal mode walks S1..S8;
                # custom mode walks Link 1..N. Never randomize this command.
                if _state.get("free_vless_mode"):
                    start = max(5, int(_state.get("free_source_index") or 4) + 1)
                    candidates = list(range(start, len(FREE_VLESS_SOURCES))) + list(range(5, min(start, len(FREE_VLESS_SOURCES))))
                    switched = False
                    for idx in candidates:
                        kill_singbox(); _state["cleaned_up"] = False
                        new_top, new_manual = discover_free_vless(binary, source_index=idx)
                        if new_top:
                            _state["free_source_index"] = idx
                            _state["free_verified_pool"] = new_top[:FREE_VLESS_COUNT]
                            proc, new_tag, ok = connect_with_fallback(binary, new_top, new_manual, False, new_top, label="Reconnected Free Vless", enable_fragment=None)
                            if ok and new_tag:
                                _state["free_vless_mode"] = True; _state["free_source_index"] = idx
                                all_outbounds = new_top; top_outbounds = new_top; manual_tag = new_manual or new_tag; last_tag = new_tag
                                save_switch_server_pool(switch_server_cache_key(True, idx), new_top)
                                switched = True; break
                    if not switched:
                        print(f"{WARN} No next Free Vless source could be connected. S1-S8 remain excluded.")
                else:
                    custom_count = len(SUB_URLS) - BUILTIN_SUB_COUNT
                    if custom_count > 0:
                        # Once personal links exist, SS is dedicated to the
                        # personal-link pool only. It never mixes S1-S8 into
                        # that cycle. If the current source is not personal,
                        # start at Link 1; otherwise continue to the next Link.
                        cur = _state.get("current_sub_index")
                        if cur is not None and BUILTIN_SUB_COUNT <= int(cur) < len(SUB_URLS):
                            start_custom = int(cur) + 1
                            if start_custom >= len(SUB_URLS):
                                start_custom = BUILTIN_SUB_COUNT
                        else:
                            start_custom = BUILTIN_SUB_COUNT
                        order = list(range(start_custom, len(SUB_URLS))) + list(range(BUILTIN_SUB_COUNT, start_custom))
                        switched = False
                        for sub_i in order:
                            new_all = fetch_all_outbounds(sub_indices=[sub_i], extended_parser=True)
                            if not new_all: continue
                            new_top, new_manual = choose_servers(new_all, binary, strict_real=True)
                            if not new_top: continue
                            kill_singbox(); _state["cleaned_up"] = False
                            np, nt, nok = connect_with_fallback(binary, new_top, new_manual, ir_bypass_enabled, new_all, label="Reconnected", enable_fragment=fragment_preset)
                            if nok and nt:
                                _state["current_sub_index"] = sub_i; all_outbounds = new_all; top_outbounds = new_top; manual_tag = new_manual or nt; last_tag = nt; proc, ok = np, nok
                                save_switch_server_pool(f"SUB:{sub_i}", new_top); switched = True; break
                        if not switched: print(f"{WARN} No next personal link could be connected.")
                retry_count = 0; elapsed_since_monitor = 0
                if last_tag:
                    render_connection_status(last_tag, all_outbounds, top_outbounds, label="Reconnected", fragment_preset=fragment_preset)
                continue

            if cmd in {"fc", "fastconnect", "fast_connect"}:
                if last_tag:
                    # FC explicitly enables Fast Connect (it is not a toggle).
                    # Save the currently connected outbound for the next startup.
                    set_fast_connect_enabled(True, last_tag, all_outbounds)
                    print(f"\\n{OK} Fast Connect : ON - saved {last_tag} for the next startup.")
                    render_connection_status(
                        last_tag, all_outbounds, top_outbounds,
                        label="Fast Connect Enabled",
                        fragment_preset=fragment_preset
                    )
                else:
                    print(f"{WARN} No active connection to save for Fast Connect.")
                elapsed_since_monitor = 0
                continue

            if cmd in {"as", "autosetting", "auto_setting"}:
                AUTO_SETTING_ENABLED = not AUTO_SETTING_ENABLED
                _state["auto_dns_rejected"] = None
                _state["as_full_pending"] = False
                _state["as_fragment_pending"] = False
                save_auto_setting_state(AUTO_SETTING_ENABLED, first_run_asked=True)
                if AUTO_SETTING_ENABLED:
                    # AS ON = DNS + Fragment + Fast Connect. Fast Connect is switched on right
                    # here; the best Fragment and DNS are picked now, on the live connection.
                    print(f"\n{OK} Auto Setting : ON")
                    set_fast_connect_enabled(True, last_tag, all_outbounds)
                    if last_tag and proc and proc.poll() is None:
                        (proc, last_tag, top_outbounds, all_outbounds, manual_tag,
                         fragment_preset) = _auto_setting_run(
                            binary, last_tag, top_outbounds, all_outbounds, manual_tag,
                            fragment_preset, full=True, visible=True)
                    else:
                        _state["as_full_pending"] = True  # no live tunnel yet: done on the next connection
                else:
                    # OFF only stops the automation. DNS / Fragment / Fast Connect stay as they
                    # are; D / F / the DNS keys still change them by hand.
                    print(f"\n{OK} Auto Setting : OFF")
                if last_tag:
                    render_connection_status(last_tag, all_outbounds, top_outbounds,
                                              label="Connected VLESS server", fragment_preset=fragment_preset)
                elapsed_since_monitor = 0
                continue

            if cmd in SUBLINK_COMMANDS:
                print(f"\n{OK} SubLink (SL) - paste a subscription link, or a single "
                      f"vless/trojan/hysteria2/hysteria/warp/wireguard link, then press Enter.")
                print("Paste Link: ", end="", flush=True)
                try:
                    pasted = input_queue.get()
                except Exception:
                    pasted = ""
                _drain_stale_input_queue()  # discard any extra lines a multi-line paste left queued
                pasted = (pasted or "").strip()
                if not pasted:
                    print(f"{WARN} No link entered - nothing added.")
                    elapsed_since_monitor = 0
                    continue

                # The new link is only added TEMPORARILY. It becomes a permanent
                # Link N (L1, L2, ...) and is written to disk only AFTER it has
                # connected successfully. If anything fails, it is rolled back.
                _prev_settings = _snapshot_optional_settings()
                _prev_free_mode = _state.get("free_vless_mode")
                _state["free_vless_mode"] = False

                SUB_URLS.append(pasted)
                link_number = len(SUB_URLS) - BUILTIN_SUB_COUNT
                SUB_NAMES.append(f"Link {link_number}")

                def _rebuild_link_commands():
                    SUB_COMMANDS.clear()
                    SUB_COMMANDS.update({f"s{i}": i - 1 for i in range(1, BUILTIN_SUB_COUNT + 1)})
                    LINK_COMMANDS.clear()
                    LINK_COMMANDS.update({f"l{i}": BUILTIN_SUB_COUNT + i - 1
                                          for i in range(1, len(SUB_URLS) - BUILTIN_SUB_COUNT + 1)})

                def _rollback_new_link():
                    if len(SUB_URLS) > BUILTIN_SUB_COUNT and SUB_URLS[-1] == pasted:
                        SUB_URLS.pop()
                        SUB_NAMES.pop()
                    _rebuild_link_commands()

                _rebuild_link_commands()
                new_sub_i0 = len(SUB_URLS) - 1
                print(f"{INFO} Connecting to the new link...")

                new_all_outbounds = fetch_all_outbounds(sub_indices=[new_sub_i0], extended_parser=True)
                if not new_all_outbounds:
                    _rollback_new_link()
                    _state["free_vless_mode"] = _prev_free_mode
                    _restore_optional_settings(_prev_settings)
                    hint = _protocol_format_hint(pasted)
                    if hint:
                        proto_name, example = hint
                        print(f"{WARN} That doesn't look like a valid {proto_name} link.")
                        print(f"{INFO} {proto_name} format: {example}")
                    else:
                        print(f"{WARN} Could not recognize that link's protocol, and it could not "
                              f"be fetched as a subscription URL either.")
                    print(f"{WARN} Connection failed. The link was NOT saved - returning to your previous connection.")
                    _countdown_then_refresh(3, last_tag, all_outbounds, top_outbounds,
                                             fragment_preset=fragment_preset,
                                             label="Connected VLESS server")
                    elapsed_since_monitor = 0
                    continue

                new_top_outbounds, new_manual_tag = choose_servers(new_all_outbounds, binary, strict_real=True)
                new_connected = False
                if new_top_outbounds:
                    kill_singbox()
                    _state["cleaned_up"] = False
                    new_proc, new_last_tag, new_ok = connect_with_fallback(
                        binary, new_top_outbounds, new_manual_tag, ir_bypass_enabled,
                        new_all_outbounds, label="Connected (new link)", enable_fragment=fragment_preset
                    )
                    new_connected = bool(new_last_tag and new_ok)
                    if new_connected:
                        proc, last_tag, ok = new_proc, new_last_tag, new_ok
                        if new_manual_tag and last_tag != new_manual_tag:
                            new_manual_tag = last_tag
                        connected_ob = next((o for o in new_all_outbounds if o["tag"] == last_tag), None)
                        proto = protocol_label(connected_ob)
                        send_notification(f"{proto} وصل شد", last_tag)
                        all_outbounds = new_all_outbounds
                        top_outbounds, manual_tag = new_top_outbounds, new_manual_tag
                        _state["current_sub_index"] = new_sub_i0
                        _release_country_binding()
                        save_custom_sublinks(SUB_URLS[BUILTIN_SUB_COUNT:])  # saved ONLY now
                        save_switch_server_pool(f"SUB:{new_sub_i0}", new_top_outbounds)
                        print(f"{OK} Connected. Saved as Link {link_number} (L{link_number}).")
                        retry_count = 0
                        elapsed_since_monitor = 0
                        continue

                # ---- Failure: drop the link, tell the user, go back to the previous connection ----
                _rollback_new_link()
                _state["free_vless_mode"] = _prev_free_mode
                print(f"{WARN} Connection failed. The link could not connect, so it was NOT saved.")
                print(f"{INFO} Returning to your previous connection...")
                if new_top_outbounds:
                    # The failed attempt had already replaced the old tunnel: stop it and bring the old one back.
                    kill_singbox()
                    _state["cleaned_up"] = False
                    _countdown_then_refresh(3, None, [], 0)
                    _restore_optional_settings(_prev_settings)
                    if last_tag and top_outbounds:
                        rp, rt, rok = connect_with_fallback(
                            binary, top_outbounds, manual_tag or last_tag, ir_bypass_enabled,
                            all_outbounds, label="Reconnected (previous connection)",
                            enable_fragment=fragment_preset, reset_options=False
                        )
                        if rt:
                            proc, last_tag, ok = rp, rt, rok
                            manual_tag = rt
                    else:
                        print(f"{WARN} There was no previous connection to return to.")
                else:
                    # The old tunnel was never touched - just refresh the screen after 3 seconds.
                    _restore_optional_settings(_prev_settings)
                    _countdown_then_refresh(3, last_tag, all_outbounds, top_outbounds,
                                             fragment_preset=fragment_preset,
                                             label="Connected VLESS server")
                retry_count = 0
                elapsed_since_monitor = 0
                continue

            if cmd in DELETE_LINK_COMMANDS:
                custom_count = len(SUB_URLS) - BUILTIN_SUB_COUNT
                if custom_count <= 0:
                    print(f"{WARN} No added links to delete yet.")
                    # Keep the warning visible briefly, then return to the
                    # normal connection screen exactly like a fresh connect.
                    time.sleep(3)
                    if last_tag:
                        render_connection_status(
                            last_tag, all_outbounds, top_outbounds,
                            label="Connected VLESS server",
                            fragment_preset=fragment_preset
                        )
                    elapsed_since_monitor = 0
                    continue

                print(f"\n{INFO} Added links:")
                for i in range(BUILTIN_SUB_COUNT, len(SUB_URLS)):
                    print(f"  Link {i - BUILTIN_SUB_COUNT + 1} (L{i - BUILTIN_SUB_COUNT + 1}): {SUB_URLS[i]}")

                print("Enter link key(s) to delete (L1, L2, L3), use '-' for multiple (e.g. L1-L3), or ALL for all: ",
                      end="", flush=True)
                try:
                    raw_keys = input_queue.get()
                except Exception:
                    raw_keys = ""
                _drain_stale_input_queue()  # discard any extra lines left queued by a multi-line paste
                raw_keys = (raw_keys or "").strip().lower()

                if not raw_keys:
                    print(f"{WARN} Cancelled.")
                    elapsed_since_monitor = 0
                    continue

                # "all" means all user-added links only; S1-S8 are never deleted.
                if raw_keys == "all":
                    delete_nums = list(range(1, custom_count + 1))
                else:
                    parts = [x.strip() for x in raw_keys.split("-") if x.strip()]
                    delete_nums = []
                    valid = True
                    for part in parts:
                        if not part.startswith("l") or not part[1:].isdigit():
                            valid = False
                            break
                        n = int(part[1:])
                        if not (1 <= n <= custom_count):
                            valid = False
                            break
                        if n not in delete_nums:
                            delete_nums.append(n)

                    if not valid or not delete_nums:
                        print(f"{WARN} Invalid link key(s). Use L1, L2, L3...; for multiple use L1-L3; or ALL.")
                        elapsed_since_monitor = 0
                        continue

                # Remember whether the currently active subscription is one of
                # the links being deleted. If so, we'll automatically fail over
                # to S1-S8 after deletion.
                current_sub_i_before = _state.get("current_sub_index")
                deleted_indices = {BUILTIN_SUB_COUNT + n - 1 for n in delete_nums}
                active_deleted = current_sub_i_before in deleted_indices

                # Delete from highest index to lowest so the indexes stay valid.
                for n in sorted(delete_nums, reverse=True):
                    del SUB_URLS[BUILTIN_SUB_COUNT + n - 1]
                    del SUB_NAMES[BUILTIN_SUB_COUNT + n - 1]

                # Re-number remaining user-added links.
                for j in range(BUILTIN_SUB_COUNT, len(SUB_NAMES)):
                    SUB_NAMES[j] = f"Link {j - BUILTIN_SUB_COUNT + 1}"

                SUB_COMMANDS.clear()
                SUB_COMMANDS.update({f"s{i}": i - 1 for i in range(1, BUILTIN_SUB_COUNT + 1)})
                LINK_COMMANDS.clear()
                LINK_COMMANDS.update({
                    f"l{i}": BUILTIN_SUB_COUNT + i - 1
                    for i in range(1, len(SUB_URLS) - BUILTIN_SUB_COUNT + 1)
                })
                save_custom_sublinks(SUB_URLS[BUILTIN_SUB_COUNT:])

                if raw_keys == "all":
                    print(f"{OK} Deleted all added links.")
                elif len(delete_nums) == 1:
                    print(f"{OK} Deleted Link {delete_nums[0]}.")
                else:
                    deleted_text = ", ".join(f"Link {n}" for n in delete_nums)
                    print(f"{OK} Deleted {deleted_text}.")

                # Give the confirmation message 3 seconds to be readable, then
                # redraw the normal connection screen just like a fresh connect.
                time.sleep(3)

                if active_deleted:
                    proc, new_tag, new_ok, new_all, new_top, new_manual, new_sub = (
                        auto_failover_to_builtin_subscriptions(binary, ir_bypass_enabled)
                    )
                    if new_tag and new_ok:
                        all_outbounds, top_outbounds, manual_tag = new_all, new_top, new_manual
                        _state["current_sub_index"] = new_sub
                        last_tag, ok = new_tag, new_ok
                        retry_count = 0
                    else:
                        elapsed_since_monitor = 0
                        continue
                else:
                    # If we deleted links other than the active one, preserve
                    # the current connection. If the active custom index moved
                    # down because an earlier link was removed, remap it.
                    if current_sub_i_before is not None and current_sub_i_before >= BUILTIN_SUB_COUNT:
                        removed_before = sum(
                            1 for idx in deleted_indices if idx < current_sub_i_before
                        )
                        _state["current_sub_index"] = current_sub_i_before - removed_before
                    elapsed_since_monitor = 0

                # render_connection_status clears the current viewport and
                # redraws the normal connected screen.
                if last_tag:
                    render_connection_status(last_tag, all_outbounds, top_outbounds,
                                              label="Connected VLESS server",
                                              fragment_preset=fragment_preset)
                continue

            if cmd in LINK_COMMANDS:
                _state["free_vless_mode"] = False
                _release_country_binding()
                sub_i = LINK_COMMANDS[cmd]
                link_name = SUB_NAMES[sub_i]
                print(f"\n{OK} Switching to {link_name} (L{sub_i - BUILTIN_SUB_COUNT + 1})...")
                new_all_outbounds = fetch_all_outbounds(sub_indices=[sub_i], extended_parser=True)
                if not new_all_outbounds:
                    hint = _protocol_format_hint(SUB_URLS[sub_i] if sub_i < len(SUB_URLS) else "")
                    if hint:
                        proto_name, example = hint
                        print(f"{WARN} That doesn't look like a valid {proto_name} link.")
                        print(f"{INFO} {proto_name} format: {example}")
                    else:
                        print(f"{WARN} Could not fetch that link - keeping the current connection.")
                    _countdown_then_refresh(5, last_tag, all_outbounds, top_outbounds,
                                             fragment_preset=fragment_preset,
                                             label="Connected VLESS server")
                    elapsed_since_monitor = 0
                    continue
                new_top_outbounds, new_manual_tag = choose_servers(new_all_outbounds, binary, strict_real=True)
                if new_top_outbounds:
                    kill_singbox()
                    _state["cleaned_up"] = False
                    _state["current_sub_index"] = sub_i
                    proc, last_tag, ok = connect_with_fallback(
                        binary, new_top_outbounds, new_manual_tag, ir_bypass_enabled,
                        new_all_outbounds, label="Reconnected", enable_fragment=fragment_preset
                    )
                    if new_manual_tag and last_tag and last_tag != new_manual_tag:
                        new_manual_tag = last_tag
                    all_outbounds = new_all_outbounds
                    top_outbounds, manual_tag = new_top_outbounds, new_manual_tag
                    save_switch_server_pool(f"SUB:{sub_i}", new_top_outbounds)
                    retry_count = 0
                else:
                    print(f"{WARN} That link's format was fine, but none of its servers answered - "
                          f"keeping the current connection.")
                    _countdown_then_refresh(5, last_tag, all_outbounds, top_outbounds,
                                             fragment_preset=fragment_preset,
                                             label="Connected VLESS server")
                elapsed_since_monitor = 0
                continue

            # Show Protocol: the list stays visible and the user gets another
            # clean prompt without a full-screen redraw.
            if cmd == "pc":
                if last_tag:
                    render_connection_status(last_tag, all_outbounds, top_outbounds,
                                              label="Connected", fragment_preset=fragment_preset,
                                              info_block="protocol", reuse_info=True)
                else:
                    _erase_submitted_input_line()
                    show_protocol_list()
                    print(f"  {_C.BOLD}{_C.CYAN}Type + Enter : {_C.RESET}", end="", flush=True)
                elapsed_since_monitor = 0
                continue

            # Search Web: shows a dedicated "Search Web 🔍:" prompt in place of the
            # generic "Type + Enter" one. The next line the user types is handled by
            # the exact same code below (Type Protocol / Type Country / Type Ping) -
            # same GitHub + Telegram sources, same FV quality gate, same silent
            # background pool-fill and source memory as every other search in the
            # program. SW only changes what the prompt says, nothing else.
            if cmd in SEARCH_WEB_COMMANDS:
                _state["sw_pending"] = True
                if last_tag:
                    render_connection_status(last_tag, all_outbounds, top_outbounds,
                                              label="Connected", fragment_preset=fragment_preset,
                                              reuse_info=True, search_web=True)
                else:
                    _erase_submitted_input_line()
                    print(f"  {_C.BOLD}{_C.CYAN}Search Web 🔍: {_C.RESET}", end="", flush=True)
                elapsed_since_monitor = 0
                continue

            # Search Web + 'udp' and/or a bare count number, combined in ANY order with an
            # optional protocol / country / @channel / website: "udp", "vless udp",
            # "Germany 6", "@vpnjey udp", "freeproxydb.com vless 6" ... 'udp' means only a
            # server that actually relays UDP is accepted (real SOCKS5 UDP-ASSOCIATE test);
            # the count means that many healthy matches are kept for Switch Server instead
            # of just one. Checked BEFORE the plain site/protocol/country dispatch below,
            # which does not understand either of these two extra tokens.
            if _state.get("sw_pending") and line and line.strip():
                udp_parsed = _parse_sw_udp_count_query(line)
                if udp_parsed:
                    _state["sw_pending"] = False
                    (channel, site_url, wanted, proto_name, country_code, country_name,
                     want_udp, want_count) = udp_parsed
                    old_proc = proc
                    old_last_tag = last_tag
                    old_all_outbounds = all_outbounds
                    old_top_outbounds = top_outbounds
                    old_manual_tag = manual_tag
                    bits = []
                    if channel:
                        bits.append(f"@{channel}")
                    if site_url:
                        bits.append(urllib.parse.urlsplit(site_url).netloc)
                    if proto_name:
                        bits.append(proto_name)
                    if country_name:
                        bits.append(f"in {country_name}")
                    if want_udp:
                        bits.append("UDP")
                    if want_count:
                        bits.append(f"x{want_count}")
                    print(f"\n{INFO} Searching: {' '.join(bits) if bits else 'any UDP server'} ...")
                    UB.record_search(protocol=wanted, country=country_code, udp=want_udp,
                                     source=(f"@{channel}" if channel else
                                             (urllib.parse.urlsplit(site_url).netloc if site_url else None)))
                    notify_label = "UDP"
                    if channel:
                        status, data = connect_by_telegram_channel_filtered(
                            binary, channel, wanted=wanted, proto_name=proto_name,
                            country_code=country_code, country_name=country_name,
                            want_udp=want_udp, want_count=want_count)
                        notify_label = f"TG @{channel}"
                    elif site_url:
                        status, data = connect_by_site(binary, site_url, wanted=wanted,
                                                       proto_name=proto_name, want_udp=want_udp,
                                                       want_count=want_count)
                        notify_label = f"Site {urllib.parse.urlsplit(site_url).netloc}"
                    elif wanted:
                        status, data = connect_by_protocol(binary, wanted, proto_name,
                                                           country=country_code, want_udp=want_udp,
                                                           want_count=want_count)
                        notify_label = f"{proto_name} {country_name or ''}".strip()
                    elif country_code:
                        status, data = connect_by_country(binary, country_code, country_name,
                                                          want_udp=want_udp, want_count=want_count)
                        notify_label = country_name or country_code
                    elif want_udp:
                        status, data = connect_by_udp_any(binary, want_count=want_count)
                    else:
                        status, data = "none", None   # a bare count with nothing else to search for
                    if status == "ok":
                        disable_speed_and_fragment()
                        fragment_preset = None
                        proc, last_tag, ok, top_outbounds, manual_tag, _src = data
                        all_outbounds = top_outbounds
                        retry_count = 0
                        if ok and AUTO_SETTING_ENABLED:
                            _state["as_full_pending"] = True
                            _state["as_visible_next"] = True
                        send_notification(notify_label, last_tag)
                    else:
                        if old_last_tag and (proc is None or proc.poll() is not None):
                            try:
                                kill_singbox()
                                _state["cleaned_up"] = False
                                proc, restored_tag, restored_ok = connect_with_fallback(
                                    binary, old_top_outbounds, old_manual_tag, ir_bypass_enabled,
                                    old_all_outbounds, label="Reconnected",
                                    enable_fragment=fragment_preset, reset_options=False)
                                if restored_tag and restored_ok:
                                    last_tag = restored_tag
                                    manual_tag = restored_tag
                                    top_outbounds = old_top_outbounds
                                    all_outbounds = old_all_outbounds
                                else:
                                    proc = old_proc
                                    last_tag = old_last_tag
                                    all_outbounds = old_all_outbounds
                                    top_outbounds = old_top_outbounds
                                    manual_tag = old_manual_tag
                            except Exception:
                                proc = old_proc
                                last_tag = old_last_tag
                                all_outbounds = old_all_outbounds
                                top_outbounds = old_top_outbounds
                                manual_tag = old_manual_tag
                        else:
                            proc = old_proc
                            last_tag = old_last_tag
                            all_outbounds = old_all_outbounds
                            top_outbounds = old_top_outbounds
                            manual_tag = old_manual_tag
                        print(f"{_C.YELLOW}{NO_RESULTS_MESSAGE}{_C.RESET}", flush=True)
                        time.sleep(NO_RESULTS_DISPLAY_SECONDS)
                    if last_tag:
                        render_connection_status(last_tag, all_outbounds, top_outbounds,
                                                  label="Connected VLESS server",
                                                  fragment_preset=fragment_preset)
                    elapsed_since_monitor = 0
                    continue

            # Search Web + a WEBSITE (freeproxydb.com, https://freeproxydb.com/ ...): crawl
            # that one site (through the VPN first - the site may be filtered), save the
            # protocols it publishes to data/site_<host>.txt, test them on the normal
            # internet and connect to the first healthy one; the rest are tested silently
            # so "Switch Server : 1 - N" holds servers of that site. Checked BEFORE Type
            # Protocol / Type Country so a site name is never mistaken for a fuzzy protocol.
            if _state.get("sw_pending") and line and line.strip():
                site_url = _parse_sw_site_query(line) if SITE_SEARCH_ENABLED else None
                if site_url:
                    _state["sw_pending"] = False
                    site_host = urllib.parse.urlsplit(site_url).netloc
                    UB.record_search(source=site_host)
                    old_proc = proc
                    old_last_tag = last_tag
                    old_all_outbounds = all_outbounds
                    old_top_outbounds = top_outbounds
                    old_manual_tag = manual_tag
                    status, data = connect_by_site(binary, site_url)
                    if status == "ok":
                        disable_speed_and_fragment()
                        fragment_preset = None
                        proc, last_tag, ok, top_outbounds, manual_tag, _src = data
                        all_outbounds = top_outbounds
                        retry_count = 0
                        if ok and AUTO_SETTING_ENABLED:
                            _state["as_full_pending"] = True
                            _state["as_visible_next"] = True
                        send_notification(f"Site {site_host}", last_tag)
                    else:
                        if old_last_tag and (proc is None or proc.poll() is not None):
                            try:
                                kill_singbox()
                                _state["cleaned_up"] = False
                                proc, restored_tag, restored_ok = connect_with_fallback(
                                    binary, old_top_outbounds, old_manual_tag, ir_bypass_enabled,
                                    old_all_outbounds, label="Reconnected",
                                    enable_fragment=fragment_preset, reset_options=False)
                                if restored_tag and restored_ok:
                                    last_tag = restored_tag
                                    manual_tag = restored_tag
                                    top_outbounds = old_top_outbounds
                                    all_outbounds = old_all_outbounds
                            except Exception:
                                proc = old_proc
                                last_tag = old_last_tag
                                all_outbounds = old_all_outbounds
                                top_outbounds = old_top_outbounds
                                manual_tag = old_manual_tag
                        else:
                            proc = old_proc
                            last_tag = old_last_tag
                            all_outbounds = old_all_outbounds
                            top_outbounds = old_top_outbounds
                            manual_tag = old_manual_tag
                        print(f"{_C.YELLOW}{NO_RESULTS_MESSAGE}{_C.RESET}", flush=True)
                        time.sleep(NO_RESULTS_DISPLAY_SECONDS)
                    if last_tag:
                        render_connection_status(last_tag, all_outbounds, top_outbounds,
                                                  label="Connected VLESS server",
                                                  fragment_preset=fragment_preset)
                    elapsed_since_monitor = 0
                    continue

            # Type Protocol: protocol names are accepted exactly like country names.
            # A prefix such as "troj" resolves to Trojan; a typo such as "trojaan"
            # is also corrected when it has one close match. Optional syntax is:
            #   protocol
            #   protocol country
            #   country protocol
            if line and line.strip():
                raw_typed = line.strip()
                words = raw_typed.split()
                proto_match = None
                country_match = None
                if len(words) == 1:
                    proto_match = resolve_protocol(words[0])
                elif len(words) >= 2:
                    # Try each token/side as protocol and treat the rest as country.
                    for split_at in range(1, len(words)):
                        left = " ".join(words[:split_at])
                        right = " ".join(words[split_at:])
                        lp, lc = resolve_protocol(left), resolve_country(right)
                        rp, rc = resolve_protocol(right), resolve_country(left)
                        if lp and lc:
                            proto_match, country_match = lp, lc
                            break
                        if rp and rc:
                            proto_match, country_match = rp, rc
                            break
                if proto_match:
                    wanted, proto_name = proto_match
                    country_code = country_match[0] if country_match else None
                    country_name = country_match[1] if country_match else None
                    extra = f" in {country_name}" if country_name else ""

                    # Preserve the current live connection while the protocol
                    # search runs. Temporary sing-box test processes are isolated
                    # and do not touch the live tunnel.
                    old_proc = proc
                    old_last_tag = last_tag
                    old_all_outbounds = all_outbounds
                    old_top_outbounds = top_outbounds
                    old_manual_tag = manual_tag

                    print(f"\n{INFO} Searching for a healthy {proto_name} server{extra}...")
                    UB.record_search(protocol=wanted, country=country_code)
                    sw_first = bool(_state.get("sw_pending"))   # typed at the Search Web prompt
                    _state["sw_pending"] = False
                    status, data = "none", None
                    if sw_first:   # Search Web: freeproxydb.com first (3 x 300), then the rest of the web
                        status, data = connect_by_site_first(binary, "protocol", wanted=wanted,
                                                             proto_name=proto_name, country=country_code,
                                                             country_name=country_name)
                    if status != "ok":
                        status, data = connect_by_protocol(binary, wanted, proto_name, country=country_code)
                    if status == "ok":
                        disable_speed_and_fragment()
                        fragment_preset = None
                        proc, last_tag, ok, top_outbounds, manual_tag, _src = data
                        all_outbounds = top_outbounds
                        retry_count = 0
                        if ok and AUTO_SETTING_ENABLED:
                            # A protocol search connects to a NEW server, same as Switch
                            # Server: Auto Setting must pick the best DNS + Fragment for it.
                            _state["as_full_pending"] = True
                            _state["as_visible_next"] = True
                        # (connect_by_protocol already bound the reserve to this protocol/country)
                        send_notification(f"{proto_name} {country_name or ''}".strip(), last_tag)
                    else:
                        # A protocol search failure is NOT an application error.
                        # Do not replace the live state, do not create a retry
                        # process, and never leave a verbose error line below the
                        # prompt. Show one short message for ~1 second, then fully
                        # redraw the existing connection screen.
                        if old_last_tag and (proc is None or proc.poll() is not None):
                            try:
                                kill_singbox()
                                _state["cleaned_up"] = False
                                proc, restored_tag, restored_ok = connect_with_fallback(
                                    binary, old_top_outbounds, old_manual_tag, ir_bypass_enabled,
                                    old_all_outbounds, label="Reconnected",
                                    enable_fragment=fragment_preset, reset_options=False
                                )
                                if restored_tag and restored_ok:
                                    last_tag = restored_tag
                                    manual_tag = restored_tag
                                    top_outbounds = old_top_outbounds
                                    all_outbounds = old_all_outbounds
                                else:
                                    proc = old_proc
                                    last_tag = old_last_tag
                                    all_outbounds = old_all_outbounds
                                    top_outbounds = old_top_outbounds
                                    manual_tag = old_manual_tag
                            except Exception:
                                proc = old_proc
                                last_tag = old_last_tag
                                all_outbounds = old_all_outbounds
                                top_outbounds = old_top_outbounds
                                manual_tag = old_manual_tag
                        else:
                            proc = old_proc
                            last_tag = old_last_tag
                            all_outbounds = old_all_outbounds
                            top_outbounds = old_top_outbounds
                            manual_tag = old_manual_tag

                        print(f"{_C.YELLOW}{NO_RESULTS_MESSAGE}{_C.RESET}", flush=True)
                        time.sleep(NO_RESULTS_DISPLAY_SECONDS)

                    if last_tag:
                        render_connection_status(last_tag, all_outbounds, top_outbounds,
                                                  label="Connected VLESS server", fragment_preset=fragment_preset)
                    elapsed_since_monitor = 0
                    continue

            # Type Ping: P318 -> search real measured latency 1..350 ms;
            # P400 -> 1..450 ms. Bare numbers remain reserved for Switch Server.
            ping_match = re.fullmatch(r"p(\d{1,5})", cmd)
            if ping_match:
                requested_ping = int(ping_match.group(1))
                if requested_ping > 10000:
                    # P<number> is a valid command shape, but this value is outside
                    # the allowed range. Treat it like any other rejected input:
                    # no error line and no screen refresh.
                    _redraw_input_prompt_in_place()
                    elapsed_since_monitor = 0
                    continue
                upper_ms = ping_search_upper_bound(requested_ping)
                print(f"\n{INFO} Searching for any protocol with real ping 1-{upper_ms} ms (P{requested_ping})...")
                UB.record_search(ping_ms=requested_ping)
                _snap = _snapshot_connection(proc, last_tag, all_outbounds, top_outbounds, manual_tag)
                sw_first = bool(_state.get("sw_pending"))   # typed at the Search Web prompt
                _state["sw_pending"] = False
                status, data, limit_ms = "none", None, upper_ms
                if sw_first:   # Search Web: freeproxydb.com first (3 x 300), then the rest of the web
                    status, data = connect_by_site_first(binary, "ping", ping_ms=requested_ping)
                if status != "ok":
                    status, data, limit_ms = connect_by_ping(binary, requested_ping)
                if status == "ok":
                    disable_speed_and_fragment()
                    fragment_preset = None
                    proc, last_tag, ok, top_outbounds, manual_tag, _src = data
                    all_outbounds = top_outbounds
                    _state["free_vless_mode"] = True
                    retry_count = 0
                    if ok and AUTO_SETTING_ENABLED:
                        # Same as Switch Server / Type Protocol: a fresh server needs its
                        # own best DNS + Fragment picked, not whatever the old one had.
                        _state["as_full_pending"] = True
                        _state["as_visible_next"] = True
                    if last_tag:
                        send_notification(f"Ping 1-{limit_ms} ms", last_tag)
                        render_connection_status(last_tag, all_outbounds, top_outbounds,
                                                  label="Connected Ping", fragment_preset=fragment_preset)
                else:
                    (proc, last_tag, all_outbounds, top_outbounds,
                     manual_tag) = _restore_previous_connection(
                        binary, ir_bypass_enabled, fragment_preset, _snap)
                    print(f"{_C.YELLOW}{NO_RESULTS_MESSAGE}{_C.RESET}", flush=True)
                    time.sleep(NO_RESULTS_DISPLAY_SECONDS)
                    if last_tag:
                        render_connection_status(last_tag, all_outbounds, top_outbounds,
                                                  label="Connected VLESS server", fragment_preset=fragment_preset)
                elapsed_since_monitor = 0
                continue

            if line and line.strip().isdigit():
                # Numeric switching is for the current candidate list. If the
                # user is in Free Vless mode, keep that mode active.
                idx = int(line.strip())
                if 1 <= idx <= len(top_outbounds):
                    picked_tag = top_outbounds[idx - 1]["tag"]
                    _ub_old = ub_capture_before_switch(last_tag, all_outbounds, top_outbounds)
                    AI.record_user_left(top_outbounds[idx - 1])
                    print(f"\n{OK} Switching to #{idx}: {picked_tag}")
                    kill_singbox()
                    _state["cleaned_up"] = False
                    # if #idx fails, tries #idx+1, #idx+2, ... (wrapping past
                    # #50 back to #1) instead of restarting from #1 every time.
                    proc, new_tag, ok = connect_with_sequential_fallback(
                        binary, top_outbounds, idx - 1, ir_bypass_enabled,
                        all_outbounds, label="Reconnected", enable_fragment=fragment_preset
                    )
                    if new_tag:
                        manual_tag = new_tag
                        last_tag = new_tag
                        if ok:
                            ub_record_after_switch(_ub_old, new_tag, all_outbounds, top_outbounds, number=idx)
                        if ok and AUTO_SETTING_ENABLED:
                            # Switch Server = a fresh connection: Auto Setting must now pick the
                            # best DNS + best Fragment for THIS server and switch them ON.
                            _state["as_full_pending"] = True
                            _state["as_visible_next"] = True
                        if ok and new_tag == picked_tag:
                            # No "Connected to #N" text here: the screen was just
                            # redrawn and anything printed now would land right
                            # after the "Type + Enter :" prompt.
                            send_notification("VLESS دوباره وصل شد", new_tag)
                            retry_count = 0
                        elif ok:
                            # The picked number was dead and the sequential fallback
                            # landed on a later one. new_idx is the number that
                            # ACTUALLY connected (4, 5, 7...), so the message adapts
                            # to however far the fallback had to go.
                            new_idx = next((j for j, ob in enumerate(top_outbounds, 1)
                                             if ob["tag"] == new_tag), None)
                            connected_to = new_idx if new_idx is not None else new_tag
                            print(f"{_C.RED}❌Number {idx} not connected{_C.RESET}"
                                  f"{_C.GREEN}✅Connected to {connected_to}{_C.RESET}", flush=True)
                            send_notification("سرور انتخابی خراب بود - سرور دیگر وصل شد", new_tag)
                            retry_count = 0
                            # Show the message for 3 seconds, then refresh the whole
                            # screen so the panel reflects the server that is now live.
                            time.sleep(3)
                            render_connection_status(new_tag, all_outbounds, top_outbounds,
                                                      label="Reconnected", fragment_preset=fragment_preset)
                        else:
                            # Every Switch Server candidate is dead. Escalate to FV:
                            # search a fresh healthy protocol pool from scratch (this
                            # naturally also refreshes the Switch Server count, since
                            # the FV pool becomes the new top_outbounds/all_outbounds).
                            kill_singbox()
                            _state["cleaned_up"] = False
                            (proc, fv_tag, fv_ok, fv_top, fv_manual,
                             fv_source_index) = connect_free_vless_with_failover(
                                binary, ir_bypass_enabled=ir_bypass_enabled, first_source_index=0,
                                enable_fragment=None
                            )
                            if fv_tag and fv_ok and fv_top:
                                _state["free_vless_mode"] = True
                                all_outbounds = fv_top
                                top_outbounds = fv_top
                                manual_tag = fv_manual or fv_tag
                                last_tag = fv_tag
                                retry_count = 0
                                source_name = get_free_vless_source_name(fv_source_index)
                                print(f"{OK} Every Switch Server candidate was dead - "
                                      f"Free Vless found a new server from {source_name}: {fv_tag}")
                                send_notification("Free Vless متصل شد", fv_tag)
                                render_connection_status(fv_tag, all_outbounds, top_outbounds,
                                                          label="Connected Free Vless", fragment_preset=fragment_preset)
                            else:
                                _state["free_vless_mode"] = True
                                all_outbounds, top_outbounds = [], []
                                manual_tag, last_tag = None, None
                                print(f"{WARN} Every Switch Server candidate was dead and Free Vless "
                                      f"found nothing either - the FV chain will retry later.")
                                wait_s = RETRY_BACKOFF_SECONDS[min(retry_count, len(RETRY_BACKOFF_SECONDS) - 1)]
                                retry_count = min(retry_count + 1, len(RETRY_BACKOFF_SECONDS) - 1)
                                proc = _FvRetryProcess(wait_s)
                                send_notification("هیچ سروری وصل نشد", "Free Vless دوباره تلاش می‌کند")
                else:
                    # Bare numbers are reserved for Switch Server.  An out-of-range
                    # number is simply ignored; the submitted line is erased and
                    # the same input prompt is restored in place.
                    _redraw_input_prompt_in_place()
                elapsed_since_monitor = 0
                continue

            # Type Country: anything left that is a country name (existing commands
            # and protocol names were handled above) starts a search in that country.
            if line and line.strip():
                found_country = resolve_country(line)
                if found_country:
                    c_code, c_name = found_country
                    print(f"\n{INFO} Searching for a healthy server in {c_name}...")
                    UB.record_search(country=c_code)
                    _snap = _snapshot_connection(proc, last_tag, all_outbounds, top_outbounds, manual_tag)
                    sw_first = bool(_state.get("sw_pending"))   # typed at the Search Web prompt
                    _state["sw_pending"] = False
                    status, data = "none", None
                    if sw_first:   # Search Web: freeproxydb.com first (3 x 300), then the rest of the web
                        status, data = connect_by_site_first(binary, "country", country=c_code,
                                                             country_name=c_name)
                    if status != "ok":
                        status, data = connect_by_country(binary, c_code, c_name)
                    if status == "ok":
                        disable_speed_and_fragment()
                        fragment_preset = None
                        proc, last_tag, ok, top_outbounds, manual_tag, _src = data
                        all_outbounds = top_outbounds
                        retry_count = 0
                        if ok and AUTO_SETTING_ENABLED:
                            # Same as Switch Server / Type Protocol / Type Ping: a fresh
                            # server needs its own best DNS + Fragment picked.
                            _state["as_full_pending"] = True
                            _state["as_visible_next"] = True
                        send_notification(f"Free Vless {c_name}", last_tag)
                    elif status == "failed" and not _snap["last_tag"]:
                        # No previous connection existed: keep the old retry behaviour.
                        _state["free_vless_mode"] = True
                        all_outbounds, top_outbounds = [], []
                        manual_tag, last_tag = None, None
                        print(f"{_C.YELLOW}{NO_RESULTS_MESSAGE}{_C.RESET}", flush=True)
                        time.sleep(NO_RESULTS_DISPLAY_SECONDS)
                        wait_s = RETRY_BACKOFF_SECONDS[min(retry_count, len(RETRY_BACKOFF_SECONDS) - 1)]
                        retry_count = min(retry_count + 1, len(RETRY_BACKOFF_SECONDS) - 1)
                        proc = _FvRetryProcess(wait_s)
                    elif status == "failed":
                        # Servers were found but none connected: bring the previous connection back.
                        (proc, last_tag, all_outbounds, top_outbounds,
                         manual_tag) = _restore_previous_connection(
                            binary, ir_bypass_enabled, fragment_preset, _snap)
                        print(f"{_C.YELLOW}{NO_RESULTS_MESSAGE}{_C.RESET}", flush=True)
                        time.sleep(NO_RESULTS_DISPLAY_SECONDS)
                        if last_tag:
                            render_connection_status(last_tag, all_outbounds, top_outbounds,
                                                      label="Connected VLESS server", fragment_preset=fragment_preset)
                    else:
                        print(f"{_C.YELLOW}{NO_RESULTS_MESSAGE}{_C.RESET}", flush=True)
                        time.sleep(NO_RESULTS_DISPLAY_SECONDS)
                        if last_tag:
                            render_connection_status(last_tag, all_outbounds, top_outbounds,
                                                      label="Connected VLESS server", fragment_preset=fragment_preset)
                    elapsed_since_monitor = 0
                    continue
                else:
                    # Search Web only ever accepts a protocol, a country, a ping
                    # (all three handled further up, before this point) or a named
                    # Telegram channel/id (an @channel token anywhere in the line,
                    # with an optional protocol / country / P<ping> code, in ANY
                    # order). Anything else typed while Search Web is active gets a
                    # warning instead of running a free-form web query.
                    was_sw_pending = _state.get("sw_pending")
                    sw_text = (line or "").strip() if was_sw_pending else ""
                    _state["sw_pending"] = False
                    sw_parsed = _parse_sw_smart_query(sw_text) if sw_text else None
                    if was_sw_pending and sw_text and not sw_parsed:
                        # Anything else typed after SW is a free-text web search.
                        _snap = _snapshot_connection(proc, last_tag, all_outbounds, top_outbounds, manual_tag)
                        print(f"\n{INFO} Searching the web for: {sw_text} ...")
                        UB.record_search(text=sw_text)
                        status, data = connect_by_web_text(binary, sw_text)
                        if status == "ok":
                            disable_speed_and_fragment()
                            fragment_preset = None
                            proc, last_tag, ok, top_outbounds, manual_tag, _src = data
                            all_outbounds = top_outbounds
                            retry_count = 0
                            if ok and AUTO_SETTING_ENABLED:
                                _state["as_full_pending"] = True
                                _state["as_visible_next"] = True
                            send_notification(f"Web {sw_text[:30]}", last_tag)
                        else:
                            (proc, last_tag, all_outbounds, top_outbounds,
                             manual_tag) = _restore_previous_connection(
                                binary, ir_bypass_enabled, fragment_preset, _snap)
                            print(f"{_C.YELLOW}{NO_RESULTS_MESSAGE}{_C.RESET}", flush=True)
                            time.sleep(NO_RESULTS_DISPLAY_SECONDS)
                        if last_tag:
                            render_connection_status(last_tag, all_outbounds, top_outbounds,
                                                      label="Connected VLESS server", fragment_preset=fragment_preset)
                        elapsed_since_monitor = 0
                        continue
                    if sw_parsed:
                        old_proc = proc
                        old_last_tag = last_tag
                        old_all_outbounds = all_outbounds
                        old_top_outbounds = top_outbounds
                        old_manual_tag = manual_tag
                        channel, wanted, proto_name, country_code, country_name, ping_ms = sw_parsed
                        bits = [f"@{channel}"]
                        if proto_name: bits.append(proto_name)
                        if country_name: bits.append(f"in {country_name}")
                        if ping_ms: bits.append(f"ping 1-{ping_search_upper_bound(ping_ms)} ms")
                        print(f"\n{INFO} Telegram channel search: {' '.join(bits)} ...")
                        UB.record_search(protocol=wanted, country=country_code, ping_ms=ping_ms,
                                         source=f"@{channel}")
                        status, data = connect_by_telegram_channel_filtered(
                            binary, channel, wanted=wanted, proto_name=proto_name,
                            country_code=country_code, country_name=country_name,
                            ping_ms=ping_ms)
                        notify_label = f"TG @{channel}"
                        if status == "ok":
                            disable_speed_and_fragment()
                            fragment_preset = None
                            proc, last_tag, ok, top_outbounds, manual_tag, _src = data
                            all_outbounds = top_outbounds
                            retry_count = 0
                            if ok and AUTO_SETTING_ENABLED:
                                _state["as_full_pending"] = True
                                _state["as_visible_next"] = True
                            send_notification(notify_label, last_tag)
                        else:
                            if old_last_tag and (proc is None or proc.poll() is not None):
                                try:
                                    kill_singbox()
                                    _state["cleaned_up"] = False
                                    proc, restored_tag, restored_ok = connect_with_fallback(
                                        binary, old_top_outbounds, old_manual_tag, ir_bypass_enabled,
                                        old_all_outbounds, label="Reconnected",
                                        enable_fragment=fragment_preset, reset_options=False)
                                    if restored_tag and restored_ok:
                                        last_tag = restored_tag
                                        manual_tag = restored_tag
                                        top_outbounds = old_top_outbounds
                                        all_outbounds = old_all_outbounds
                                except Exception:
                                    proc = old_proc
                                    last_tag = old_last_tag
                                    all_outbounds = old_all_outbounds
                                    top_outbounds = old_top_outbounds
                                    manual_tag = old_manual_tag
                            else:
                                proc = old_proc
                                last_tag = old_last_tag
                                all_outbounds = old_all_outbounds
                                top_outbounds = old_top_outbounds
                                manual_tag = old_manual_tag
                            print(f"{_C.YELLOW}{NO_RESULTS_MESSAGE}{_C.RESET}", flush=True)
                            time.sleep(NO_RESULTS_DISPLAY_SECONDS)
                        if last_tag:
                            render_connection_status(last_tag, all_outbounds, top_outbounds,
                                                      label="Connected VLESS server", fragment_preset=fragment_preset)
                        elapsed_since_monitor = 0
                        continue
                    # Unknown commands / random text are rejected.  Do not run
                    # anything, print an error, or advance to a new line.  Replace
                    # the submitted input with the same clean prompt in place.
                    _redraw_input_prompt_in_place()
                    elapsed_since_monitor = 0
                    continue

            health_dead = bool(_RESERVE is not None and _state.get("free_vless_mode")
                               and _RESERVE.consume_health_dead(proc))
            if proc.poll() is not None or health_dead:
                sys.stdout.write("\n")  # finalize any unfinished pulse line before printing

                # Free Vless: the reserve found earlier in the background goes first.
                if _state.get("free_vless_mode") and _RESERVE is not None and _RESERVE.count() > 0:
                    res = reserve_failover(binary, _RESERVE)
                    if res:
                        proc, last_tag, ok, top_outbounds, manual_tag = res
                        all_outbounds = top_outbounds
                        retry_count = 0
                        if ok and AUTO_SETTING_ENABLED:
                            _state["as_full_pending"] = True
                            _state["as_visible_next"] = True
                        send_notification("Free Vless دوباره وصل شد", last_tag)
                        elapsed_since_monitor = 0
                        continue

                # Bound to a protocol (Type Protocol): find another server of the same
                # protocol (and country) first - silently, the user already chose it once.
                if _state.get("free_vless_mode") and _RESERVE is not None and _RESERVE.protocol:
                    p_wanted = _RESERVE.protocol
                    p_name = _RESERVE.protocol_name or p_wanted
                    p_code = _RESERVE.country
                    status, data = connect_by_protocol(binary, p_wanted, p_name, country=p_code,
                                                       silent=True, label="Reconnected Free Vless")
                    if status == "ok":
                        proc, last_tag, ok, top_outbounds, manual_tag, _src = data
                        all_outbounds = top_outbounds
                        retry_count = 0
                        if ok and AUTO_SETTING_ENABLED:
                            _state["as_full_pending"] = True
                            _state["as_visible_next"] = True
                        send_notification(f"{p_name}", last_tag)
                        elapsed_since_monitor = 0
                        continue
                    _RESERVE.set_binding()  # none left: continue with the normal Free Vless chain

                # Bound to a country (Type Country): find another server there first.
                # This retry is silent on purpose - the user already picked the
                # country once; there's nothing new to tell them until it's done.
                if _state.get("free_vless_mode") and _RESERVE is not None and _RESERVE.country:
                    c_code, c_name = _RESERVE.country, (_RESERVE.country_name or _RESERVE.country)
                    status, data = connect_by_country(binary, c_code, c_name,
                                                       label="Reconnected Free Vless", silent=True)
                    if status == "ok":
                        proc, last_tag, ok, top_outbounds, manual_tag, _src = data
                        all_outbounds = top_outbounds
                        retry_count = 0
                        if ok and AUTO_SETTING_ENABLED:
                            _state["as_full_pending"] = True
                            _state["as_visible_next"] = True
                        send_notification(f"Free Vless {c_name}", last_tag)
                        elapsed_since_monitor = 0
                        continue
                    _RESERVE.set_binding()  # none left: continue with the normal Free Vless chain

                # IMPORTANT: In Free Vless mode the current 6-10 nodes are a
                # temporary pool. If the whole pool dies later, never retry that
                # same dead pool. Move through the dedicated FV source chain.
                if _state.get("free_vless_mode"):
                    print(f"{WARN} Free Vless pool stopped working - NOT retrying the same {len(top_outbounds)} nodes.")
                    send_notification("Free Vless قطع شد", "در حال تست منبع Free Vless بعدی")
                    kill_singbox()
                    _state["cleaned_up"] = False

                    (proc, new_tag, ok, new_top_outbounds, new_manual_tag, new_source_index) = connect_free_vless_with_failover(
                        binary, ir_bypass_enabled=False, first_source_index=None,
                        enable_fragment=None
                    )

                    if new_tag and ok and new_top_outbounds:
                        all_outbounds = new_top_outbounds
                        top_outbounds = new_top_outbounds
                        manual_tag = new_manual_tag or new_tag
                        last_tag = new_tag
                        _state["free_vless_mode"] = True
                        retry_count = 0
                        source_name = get_free_vless_source_name(new_source_index)
                        print(f"{OK} Free Vless: {source_name} connected after the previous pool died.")
                        send_notification("Free Vless دوباره وصل شد", new_tag)
                        render_connection_status(new_tag, all_outbounds, top_outbounds,
                                                  label="Reconnected Free Vless", fragment_preset=None)
                    else:
                        _state["free_vless_mode"] = True
                        all_outbounds = []
                        top_outbounds = []
                        manual_tag = None
                        last_tag = None
                        print(f"{WARN} No Free Vless source produced a live connection. S1-S8 remain completely excluded.")
                        wait_s = RETRY_BACKOFF_SECONDS[min(retry_count, len(RETRY_BACKOFF_SECONDS) - 1)]
                        retry_count = min(retry_count + 1, len(RETRY_BACKOFF_SECONDS) - 1)
                        proc = _FvRetryProcess(wait_s)

                    elapsed_since_monitor = 0
                    continue

                # If a user-added Link (S9+) dies, do not keep retrying it or ask for R:
                # automatically run the built-in S1-S8 failover.
                current_sub_i = _state.get("current_sub_index")
                if current_sub_i is not None and current_sub_i >= BUILTIN_SUB_COUNT:
                    proc, new_tag, ok, new_all, new_top, new_manual, new_sub = auto_failover_to_builtin_subscriptions(binary, ir_bypass_enabled)
                    if new_tag and ok:
                        all_outbounds, top_outbounds, manual_tag = new_all, new_top, new_manual
                        _state["current_sub_index"] = new_sub
                        last_tag = new_tag
                        retry_count = 0
                        render_connection_status(new_tag, all_outbounds, top_outbounds,
                                                  label="Auto R Reconnected", fragment_preset=fragment_preset)
                    elapsed_since_monitor = 0
                    continue

                # Normal (non-FV) mode keeps the old reconnect behavior.
                wait_s = RETRY_BACKOFF_SECONDS[min(retry_count, len(RETRY_BACKOFF_SECONDS) - 1)]
                retry_count += 1
                print(f"{WARN} sing-box exited unexpectedly. Reconnecting in {wait_s}s "
                      f"(attempt {retry_count})...")
                send_notification("VLESS قطع شد", f"تلاش دوباره تا {wait_s} ثانیه دیگر...")
                time.sleep(wait_s)

                proc, new_tag, ok = connect_with_fallback(
                    binary, top_outbounds, manual_tag, ir_bypass_enabled, all_outbounds,
                    label="Reconnected", enable_fragment=fragment_preset
                )
                if manual_tag and new_tag and new_tag != manual_tag:
                    manual_tag = new_tag
                if new_tag:
                    send_notification("VLESS دوباره وصل شد" if ok else "VLESS با مشکل وصل شد", new_tag)
                    last_tag = new_tag
                    retry_count = 0
                else:
                    print(f"{WARN} Still could not confirm a selection after reconnecting.")

                elapsed_since_monitor = 0
                continue

            if not manual_tag and elapsed_since_monitor >= MONITOR_INTERVAL_SECONDS:
                elapsed_since_monitor = 0

                current_tag = get_current_selection()
                if current_tag and current_tag != last_tag:
                    sys.stdout.write("\n")  # finalize any unfinished pulse line before printing
                    render_connection_status(current_tag, all_outbounds, top_outbounds,
                                              label="Active server changed", fragment_preset=fragment_preset)
                    send_notification("سرور VLESS عوض شد", current_tag)
                    last_tag = current_tag

    except KeyboardInterrupt:
        print(f"\n{OK} Stopping...")
    except Exception as e:
        print(f"{WARN} Unexpected error: {e}")
    finally:
        # runs on normal exit, Ctrl+C, or any crash - guarantees the sing-box
        # listening ports are released.
        if _RESERVE is not None:
            _RESERVE.stop()
        kill_singbox()
        kill_test_procs()
        release_wake_lock()


if __name__ == "__main__":
    main()
