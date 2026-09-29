"""Protocol URI parsers used by Ramin VPN.

This module is intentionally independent from the application core.  The
extended parser is used by Free Vless and SubLink; the built-in S1-S8 path
continues to pass extended=False exactly as before.
"""
import base64
import json
import re
import urllib.parse

def parse_vless_uri(uri: str, index: int, extended: bool = False):
    """Converts a vless:// link into a sing-box outbound.

    extended=True is intentionally used only by Free Vless and user-added
    SubLinks. The built-in S1-S8 path keeps the original parser unchanged.
    """
    if not uri.startswith("vless://"):
        return None

    body = uri[len("vless://"):]

    if "#" in body:
        body, remark = body.split("#", 1)
        remark = urllib.parse.unquote(remark)
    else:
        remark = f"vless-{index}"

    # tags must be unique
    remark = f"{index:02d}. {remark}".strip()

    if "@" not in body:
        return None
    uuid_part, rest = body.split("@", 1)

    if "?" in rest:
        hostport, query = rest.split("?", 1)
    else:
        hostport, query = rest, ""

    if ":" not in hostport:
        return None
    address, port_str = hostport.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError:
        return None

    params = urllib.parse.parse_qs(query, keep_blank_values=True)

    def get(key, default=""):
        v = params.get(key)
        return v[0] if v else default

    net_type = get("type", "tcp").lower()
    security = get("security", "none").lower()
    host_header = get("host", address)
    sni = get("sni", host_header)
    path = get("path", "/")
    alpn = get("alpn", "")
    fp = get("fp", "")
    flow = get("flow", "")
    early_data_header = get("eh", "")
    early_data = get("ed", "0")

    outbound = {
        "type": "vless",
        "tag": remark,
        "server": address,
        "server_port": port,
        "uuid": uuid_part,
    }

    if security == "tls":
        tls = {"enabled": True, "server_name": sni}
        if alpn:
            tls["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp.lower()}
        outbound["tls"] = tls

    # Extended parsing is deliberately isolated from S1-S8. It covers the
    # common Reality/VLESS transport parameters found in public Free Vless
    # and user-added SubLink URLs. sing-box requires Reality public_key and
    # short_id on the client side.
    if extended and security == "reality":
        tls = {"enabled": True, "server_name": sni}
        if alpn:
            tls["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp.lower()}
        pbk = get("pbk", get("publicKey", ""))
        sid = get("sid", get("shortId", ""))
        if not pbk or sid is None:
            return None
        tls["reality"] = {"enabled": True, "public_key": pbk, "short_id": sid}
        outbound["tls"] = tls

    if extended and flow:
        outbound["flow"] = flow

    # Transports sing-box has no client for (Xray-only): skip the link now
    # instead of spending a whole verification cycle on a guaranteed failure.
    if extended and net_type in {"xhttp", "splithttp", "kcp", "mkcp", "quic"}:
        return None
    if net_type == "raw":
        net_type = "tcp"

    # UDP-over-VLESS packet encoding (needed for UDP such as QUIC/voice/DNS
    # to work at the same time as TCP). Only forwarded when the link says so.
    packet_encoding = (get("packetEncoding", get("packet_encoding", ""))).lower()
    if packet_encoding in ("xudp", "packetaddr"):
        outbound["packet_encoding"] = packet_encoding

    if net_type == "ws":
        transport = {
            "type": "ws",
            "path": path,
            "headers": {"Host": host_header},
        }
        try:
            ed_int = int(early_data)
        except ValueError:
            ed_int = 0
        if ed_int:
            transport["max_early_data"] = ed_int
            transport["early_data_header_name"] = early_data_header or "Sec-WebSocket-Protocol"
        outbound["transport"] = transport
    elif extended and net_type == "grpc":
        service_name = get("serviceName", path.lstrip("/")) or path.lstrip("/")
        outbound["transport"] = {"type": "grpc", "service_name": service_name}
    elif extended and net_type in {"http", "h2"}:
        hosts = [h.strip() for h in host_header.split(",") if h.strip()]
        outbound["transport"] = {"type": "http", "host": hosts, "path": path}
    elif extended and net_type == "httpupgrade":
        outbound["transport"] = {"type": "httpupgrade", "path": path, "host": host_header}

    return outbound


def parse_trojan_uri(uri: str, index: int):
    """Converts a single trojan:// link into a sing-box-compatible outbound."""
    if not uri.startswith("trojan://"):
        return None

    body = uri[len("trojan://"):]

    if "#" in body:
        body, remark = body.split("#", 1)
        remark = urllib.parse.unquote(remark)
    else:
        remark = f"trojan-{index}"

    remark = f"{index:02d}. {remark}".strip()

    if "@" not in body:
        return None
    password, rest = body.split("@", 1)
    password = urllib.parse.unquote(password)

    if "?" in rest:
        hostport, query = rest.split("?", 1)
    else:
        hostport, query = rest, ""

    if ":" not in hostport:
        return None
    address, port_str = hostport.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError:
        return None

    params = urllib.parse.parse_qs(query, keep_blank_values=True)

    def get(key, default=""):
        v = params.get(key)
        return v[0] if v else default

    net_type = get("type", "tcp")
    security = get("security", "tls")  # trojan is TLS by default
    host_header = get("host", address)
    sni = get("sni", host_header)
    path = get("path", "/")
    alpn = get("alpn", "")
    fp = get("fp", "")
    early_data_header = get("eh", "")
    early_data = get("ed", "0")

    outbound = {
        "type": "trojan",
        "tag": remark,
        "server": address,
        "server_port": port,
        "password": password,
    }

    if security != "none":
        tls = {"enabled": True, "server_name": sni}
        if alpn:
            tls["alpn"] = [a for a in alpn.split(",") if a]
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}
        outbound["tls"] = tls

    if net_type == "ws":
        transport = {
            "type": "ws",
            "path": path,
            "headers": {"Host": host_header},
        }
        try:
            ed_int = int(early_data)
        except ValueError:
            ed_int = 0
        if ed_int:
            transport["max_early_data"] = ed_int
            transport["early_data_header_name"] = early_data_header or "Sec-WebSocket-Protocol"
        outbound["transport"] = transport

    return outbound


def parse_hysteria2_uri(uri: str, index: int):
    """Converts a hysteria2:// (or hy2://) link into a sing-box-compatible
    outbound. Hysteria2's URI format is standardized (unlike v1's), close to
    trojan's: hysteria2://password@host:port/?insecure=1&obfs=salamander&
    obfs-password=xxx&sni=xxx&pinSHA256=xxx#remark
    Spec: https://v2.hysteria.network/docs/developers/URI-Scheme/
    """
    scheme = "hysteria2://" if uri.startswith("hysteria2://") else "hy2://"
    if not uri.startswith(scheme):
        return None

    body = uri[len(scheme):]

    if "#" in body:
        body, remark = body.split("#", 1)
        remark = urllib.parse.unquote(remark)
    else:
        remark = f"hysteria2-{index}"

    remark = f"{index:02d}. {remark}".strip()

    if "@" not in body:
        return None
    password, rest = body.split("@", 1)
    password = urllib.parse.unquote(password)

    if "?" in rest:
        hostport, query = rest.split("?", 1)
    else:
        hostport, query = rest, ""
    if "/" in hostport:
        hostport = hostport.split("/", 1)[0]  # drop an optional trailing path segment

    address, port = _split_host_port(hostport)
    authority_ranges = []
    if address is None:
        # multi-port authority: host:20000-30000 or host:443,5000-6000
        h, _, p = hostport.rpartition(":")
        authority_ranges = _hy2_server_ports(p)
        if not h or not authority_ranges:
            return None
        address = h.strip("[]")
        port = int(authority_ranges[0].split(":")[0])

    params = urllib.parse.parse_qs(query, keep_blank_values=True)

    def get(key, default=""):
        v = params.get(key)
        return v[0] if v else default

    sni = get("sni", address)
    insecure = get("insecure", "0") in ("1", "true", "True")
    obfs_type = get("obfs", "").lower()
    obfs_password = get("obfs-password", "")
    up_mbps = get("upmbps", "") or get("up", "")
    down_mbps = get("downmbps", "") or get("down", "")
    pinsha256 = get("pinSHA256", "")
    mport = get("mport", "") or get("ports", "") or get("server_ports", "") or ",".join(authority_ranges)
    hop_interval = get("hop-interval", "") or get("hop_interval", "")
    hop_interval_max = get("hop-interval-max", "") or get("hop_interval_max", "")
    bbr_profile = get("bbr-profile", "") or get("bbr_profile", "")

    outbound = {
        "type": "hysteria2",
        "tag": remark,
        "server": address,
        "server_port": port,
        "password": password,
        "tls": {"enabled": True, "server_name": sni, "insecure": insecure},
    }
    # sing-box 1.14: obfs.type is "salamander" or the new "gecko". Anything
    # else would make the whole config fail validation, so it is dropped.
    if obfs_type in ("salamander", "gecko"):
        outbound["obfs"] = {"type": obfs_type, "password": obfs_password}
    # Port hopping (mport=20000-30000 or 443,5000-6000). sing-box wants
    # "start:end" strings in server_ports; server_port is then ignored.
    server_ports = _hy2_server_ports(mport)
    if server_ports:
        outbound["server_ports"] = server_ports
        if hop_interval and _is_go_duration(hop_interval):
            outbound["hop_interval"] = hop_interval
        if hop_interval_max and _is_go_duration(hop_interval_max):
            outbound["hop_interval_max"] = hop_interval_max  # sing-box 1.14+
    if bbr_profile in ("conservative", "standard", "aggressive"):
        outbound["bbr_profile"] = bbr_profile  # sing-box 1.14+
    if up_mbps:
        v = _leading_int(up_mbps)
        if v:
            outbound["up_mbps"] = v
    if down_mbps:
        v = _leading_int(down_mbps)
        if v:
            outbound["down_mbps"] = v
    if pinsha256:
        # pinSHA256 in a hysteria2:// link is the SHA-256 of the server's
        # *certificate*. sing-box can only pin the *public key*
        # (tls.certificate_public_key_sha256, sing-box 1.13+) - the two
        # hashes are different, so a certificate pin can not be converted.
        # (The old code wrote it into tls.certificate, which expects a PEM
        # certificate and made sing-box reject the whole config.) Links that
        # carry a pin are self-signed servers, so verification is relaxed.
        outbound["tls"]["insecure"] = True

    return outbound


def _leading_int(text: str) -> int:
    """'100', '100 mbps', '100Mbps' -> 100 (0 when there is no number)."""
    m = re.match(r"\s*(\d+)", str(text or ""))
    return int(m.group(1)) if m else 0


def _is_go_duration(text: str) -> bool:
    return bool(re.fullmatch(r"(\d+(\.\d+)?(ns|us|ms|s|m|h))+", str(text or "").strip()))


def _hy2_server_ports(mport: str) -> list:
    """'20000-30000,443' -> ['20000:30000', '443:443']"""
    out = []
    for part in str(mport or "").replace(";", ",").split(","):
        part = part.strip().replace("-", ":")
        if not part:
            continue
        if ":" in part:
            a, _, b = part.partition(":")
        else:
            a, b = part, part
        if a.isdigit() and b.isdigit() and 0 < int(a) <= int(b) <= 65535:
            out.append(f"{int(a)}:{int(b)}")
    return out


def parse_hysteria_uri(uri: str, index: int):
    """Converts a hysteria:// (v1) link into a sing-box-compatible outbound.
    Unlike v2, Hysteria 1's URI format was never officially standardized -
    different panels/clients emit slightly different query params. This
    covers the common NekoBox/v2rayN-style layout:
    hysteria://host:port?auth=xxx&peer=sni&insecure=1&upmbps=100&
    downmbps=100&alpn=h3&obfs=xxx&protocol=udp#remark
    Some panels instead put the auth before an '@', trojan-style - both are
    handled below.
    """
    if not (uri.startswith("hysteria://") or uri.startswith("hy://")):
        return None

    scheme = "hysteria://" if uri.startswith("hysteria://") else "hy://"
    body = uri[len(scheme):]

    if "#" in body:
        body, remark = body.split("#", 1)
        remark = urllib.parse.unquote(remark)
    else:
        remark = f"hysteria-{index}"

    remark = f"{index:02d}. {remark}".strip()

    auth_from_userinfo = ""
    if "@" in body:
        auth_from_userinfo, body = body.split("@", 1)
        auth_from_userinfo = urllib.parse.unquote(auth_from_userinfo)

    if "?" in body:
        hostport, query = body.split("?", 1)
    else:
        hostport, query = body, ""

    if ":" not in hostport:
        return None
    address, port_str = hostport.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError:
        return None

    params = urllib.parse.parse_qs(query, keep_blank_values=True)

    def get(key, default=""):
        v = params.get(key)
        return v[0] if v else default

    auth = auth_from_userinfo or get("auth", "") or get("auth_str", "")
    sni = get("peer", "") or get("sni", "") or address
    insecure = get("insecure", "0") in ("1", "true", "True")
    obfs = get("obfs", "")
    alpn = get("alpn", "")
    # Hysteria 1 requires bandwidth hints (the server enforces/negotiates
    # against them); when a link omits them, fall back to conservative
    # defaults rather than sending 0, which some servers reject outright.
    up_mbps = get("upmbps", "") or get("up", "") or "10"
    down_mbps = get("downmbps", "") or get("down", "") or "50"

    outbound = {
        "type": "hysteria",
        "tag": remark,
        "server": address,
        "server_port": port,
        "auth_str": auth,
        "tls": {"enabled": True, "server_name": sni, "insecure": insecure},
    }
    if obfs:
        outbound["obfs"] = obfs
    if alpn:
        outbound["tls"]["alpn"] = [a for a in alpn.split(",") if a]
    try:
        outbound["up_mbps"] = int(up_mbps)
    except ValueError:
        outbound["up_mbps"] = 10
    try:
        outbound["down_mbps"] = int(down_mbps)
    except ValueError:
        outbound["down_mbps"] = 50

    return outbound


def _looks_like_cloudflare_warp(host: str) -> bool:
    """Cloudflare WARP's endpoints are well-known - engage.cloudflareclient.com,
    or the 162.159.x.x / 188.114.x.x / 2606:4700:... anycast ranges - so a
    plain wireguard:// link pointed at one of these is WARP even if the
    scheme used wasn't literally 'warp://'."""
    host = (host or "").lower()
    return (
        "cloudflareclient.com" in host
        or host.startswith("162.159.")
        or host.startswith("188.114.")
        or host.startswith("2606:4700")
    )


def _normalize_wg_address(addr: str) -> str:
    """WireGuard endpoint `address` entries must be IP *prefixes*. Some links
    list a bare IP (10.0.0.2) - turn it into /32 (IPv4) or /128 (IPv6)."""
    addr = (addr or "").strip()
    if not addr:
        return ""
    if "/" in addr:
        return addr
    return addr + ("/128" if ":" in addr else "/32")


def _split_host_port(hostport: str):
    """Split host:port, including bracketed IPv6 ([2606:4700::1]:2408)."""
    hostport = (hostport or "").strip()
    if hostport.startswith("["):
        close = hostport.find("]")
        if close == -1:
            return None, None
        host = hostport[1:close]
        rest = hostport[close + 1:]
        if not rest.startswith(":"):
            return None, None
        port_str = rest[1:]
    else:
        if ":" not in hostport:
            return None, None
        host, port_str = hostport.rsplit(":", 1)
    try:
        return host, int(port_str)
    except ValueError:
        return None, None


def parse_wireguard_uri(uri: str, index: int):
    """Converts a wireguard:// (or warp://, for Cloudflare WARP identities
    shared the same way) link into Ramin VPN's INTERNAL WireGuard record
    (type "wireguard"; server/server_port/local_address/private_key/
    peer_public_key/...). Layout (matches what NekoBox/v2rayNG/hiddify-style
    clients export a WARP/WireGuard identity as):
    wireguard://private_key@host:port/?address=10.0.0.2/32,fd00::2/128&
    publickey=peer_public_key&reserved=1,2,3&mtu=1280#remark

    IMPORTANT (sing-box >= 1.13): the legacy "wireguard" OUTBOUND was
    removed. WireGuard now exists only as an ENDPOINT. The internal record
    is kept in the flat, outbound-like shape so the whole pipeline (ranking,
    verification, tags, display) keeps working unchanged; it is converted to
    a real endpoint by wireguard_to_endpoint() / apply_endpoints() at the
    moment a sing-box config is written.

    A WARP identity is just a WireGuard peer pointed at Cloudflare's network -
    the tag gets a 'WARP-' prefix when it's recognized as one, purely so the
    connection display can clearly say "Connected to WARP" (see
    print_connection_info's protocol_label())."""
    is_warp_scheme = uri.startswith("warp://")
    scheme = "warp://" if is_warp_scheme else "wireguard://"
    if not uri.startswith(scheme):
        return None

    body = uri[len(scheme):]

    if "#" in body:
        body, remark = body.split("#", 1)
        remark = urllib.parse.unquote(remark)
    else:
        remark = "WARP" if is_warp_scheme else f"wireguard-{index}"

    if "@" not in body:
        return None
    private_key, rest = body.split("@", 1)
    private_key = urllib.parse.unquote(private_key)

    if "?" in rest:
        hostport, query = rest.split("?", 1)
    else:
        hostport, query = rest, ""
    if "/" in hostport:
        hostport = hostport.split("/", 1)[0]  # drop an optional trailing path segment

    address, port = _split_host_port(hostport)
    if not address or port is None:
        return None

    params = urllib.parse.parse_qs(query, keep_blank_values=True)

    def get(*keys, default=""):
        for k in keys:
            v = params.get(k)
            if v:
                return v[0]
        return default

    public_key = get("publickey", "public_key", "pbk")
    local_addr = get("address", "addr", "ip")
    reserved_raw = get("reserved", "")
    mtu_raw = get("mtu", default="1280")
    psk = get("presharedkey", "preshared_key", "pre_shared_key", "psk")
    keepalive_raw = get("keepalive", "persistent_keepalive", "persistentkeepalive")

    if not public_key or not local_addr:
        return None  # not enough to actually build a working peer

    local_addresses = [_normalize_wg_address(a) for a in local_addr.split(",")]
    local_addresses = [a for a in local_addresses if a]
    if not local_addresses:
        return None

    reserved = None
    if reserved_raw:
        try:
            reserved = [int(x.strip()) for x in reserved_raw.split(",")]
            if len(reserved) != 3 or any(not 0 <= b <= 255 for b in reserved):
                reserved = None
        except ValueError:
            reserved = None

    try:
        mtu = int(mtu_raw)
    except ValueError:
        mtu = 1280

    is_warp = is_warp_scheme or _looks_like_cloudflare_warp(address)
    tag_prefix = "WARP-" if is_warp else ""
    tag = f"{tag_prefix}{index:02d}. {remark}".strip()

    outbound = {
        "type": "wireguard",
        "tag": tag,
        "server": address,
        "server_port": port,
        "local_address": local_addresses,
        "private_key": private_key,
        "peer_public_key": public_key,
        "mtu": mtu,
    }
    if reserved:
        outbound["reserved"] = reserved
    if psk:
        outbound["pre_shared_key"] = psk
    try:
        keepalive = int(keepalive_raw) if keepalive_raw else 0
    except ValueError:
        keepalive = 0
    if keepalive > 0:
        outbound["persistent_keepalive_interval"] = keepalive

    return outbound


def wireguard_to_endpoint(ob: dict) -> dict:
    """Convert Ramin VPN's flat internal WireGuard record into a sing-box
    (>= 1.11, REQUIRED from 1.13) WireGuard *endpoint*:

      {"type": "wireguard", "tag": ..., "address": [prefixes], "private_key": ...,
       "mtu": ..., "peers": [{"address", "port", "public_key", "allowed_ips",
       "reserved", "pre_shared_key", "persistent_keepalive_interval"}]}

    One WireGuard endpoint carries TCP *and* UDP (and ICMP) through the same
    userspace tunnel, so a single endpoint serves both at the same time.
    Any key that is not part of the internal record (dial fields such as
    domain_resolver, detour, udp_timeout ...) is passed through untouched.
    """
    peer = {
        "address": ob["server"],
        "port": int(ob["server_port"]),
        "public_key": ob["peer_public_key"],
        "allowed_ips": list(ob.get("allowed_ips") or ["0.0.0.0/0", "::/0"]),
    }
    if ob.get("pre_shared_key"):
        peer["pre_shared_key"] = ob["pre_shared_key"]
    if ob.get("reserved"):
        peer["reserved"] = list(ob["reserved"])
    if ob.get("persistent_keepalive_interval"):
        peer["persistent_keepalive_interval"] = int(ob["persistent_keepalive_interval"])

    internal_keys = {
        "type", "tag", "server", "server_port", "local_address", "private_key",
        "peer_public_key", "mtu", "reserved", "pre_shared_key",
        "persistent_keepalive_interval", "allowed_ips",
    }
    ep = {
        "type": "wireguard",
        "tag": ob["tag"],
        "address": [_normalize_wg_address(a) for a in ob.get("local_address", [])],
        "private_key": ob["private_key"],
        "mtu": int(ob.get("mtu") or 1280),
        "peers": [peer],
    }
    for k, v in ob.items():
        if k not in internal_keys:
            ep[k] = v
    return ep


def apply_endpoints(config: dict) -> dict:
    """Final pass over a sing-box config dict (call it right before json.dump).

    Moves every WireGuard record out of "outbounds" into the top-level
    "endpoints" list, converted to the endpoint schema. Everything else is
    left alone. Idempotent, and a no-op when the config has no WireGuard
    entry. Endpoints are referenced by tag exactly like outbounds (route
    "final"/rules, urltest/selector members, DNS "detour"), so nothing else
    in the config has to change."""
    outbounds = config.get("outbounds") or []
    keep, endpoints = [], list(config.get("endpoints") or [])
    for ob in outbounds:
        if isinstance(ob, dict) and ob.get("type") == "wireguard" and "peer_public_key" in ob:
            endpoints.append(wireguard_to_endpoint(ob))
        else:
            keep.append(ob)
    config["outbounds"] = keep
    if endpoints:
        config["endpoints"] = endpoints
    return config


def parse_vmess_uri(uri: str, index: int):
    """Converts a vmess:// link (base64-encoded JSON - the format basically
    every V2Ray/VMess sharing tool and subscription aggregator uses) into a
    sing-box-compatible outbound. Covers the common transports (tcp, ws,
    grpc, h2/http); anything else falls back to plain tcp."""
    if not uri.startswith("vmess://"):
        return None
    body = uri[len("vmess://"):]
    try:
        padded = body + "=" * (-len(body) % 4)
        data = json.loads(base64.b64decode(padded).decode("utf-8", errors="ignore"))
    except Exception:
        return None

    address = data.get("add")
    try:
        port = int(data.get("port"))
    except (TypeError, ValueError):
        return None
    uuid = data.get("id")
    if not address or not port or not uuid:
        return None

    remark = data.get("ps") or f"vmess-{index}"
    tag = f"{index:02d}. {remark}".strip()

    try:
        alter_id = int(data.get("aid", 0) or 0)
    except (TypeError, ValueError):
        alter_id = 0
    security = data.get("scy") or "auto"
    net = (data.get("net") or "tcp").lower()
    host = data.get("host", "")
    path = data.get("path", "")
    sni = data.get("sni") or host or address
    uses_tls = (data.get("tls") or "").lower() == "tls"

    outbound = {
        "type": "vmess",
        "tag": tag,
        "server": address,
        "server_port": port,
        "uuid": uuid,
        "security": security,
        "alter_id": alter_id,
    }

    if net == "ws":
        transport = {"type": "ws", "path": path or "/"}
        if host:
            transport["headers"] = {"Host": host}
        outbound["transport"] = transport
    elif net == "grpc":
        outbound["transport"] = {"type": "grpc", "service_name": path or ""}
    elif net in ("h2", "http"):
        transport = {"type": "http"}
        if host:
            transport["host"] = [host]
        if path:
            transport["path"] = path
        outbound["transport"] = transport
    # "tcp" (and anything unrecognized) -> no transport block = plain TCP

    if uses_tls:
        outbound["tls"] = {"enabled": True, "server_name": sni}
        fp = data.get("fp")
        if fp:
            outbound["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
        alpn = data.get("alpn")
        if alpn:
            outbound["tls"]["alpn"] = [a for a in alpn.split(",") if a]

    return outbound


def parse_ss_uri(uri: str, index: int):
    """Converts a ss:// (Shadowsocks) link into a sing-box-compatible
    outbound. Supports the common SIP002 form (ss://base64(method:password)
    @host:port) and the older fully-base64-encoded form (ss://base64(method:
    password@host:port)) that some aggregators still emit, plus an optional
    ?plugin=... query param."""
    if not uri.startswith("ss://"):
        return None
    body = uri[len("ss://"):]

    if "#" in body:
        body, remark = body.split("#", 1)
        remark = urllib.parse.unquote(remark)
    else:
        remark = f"ss-{index}"
    tag = f"{index:02d}. {remark}".strip()

    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    if "/" in body:
        body = body.split("/", 1)[0]  # drop an optional trailing path segment

    method = password = address = None
    port = None

    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        try:
            decoded = base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode("utf-8")
        except Exception:
            decoded = urllib.parse.unquote(userinfo)  # some links leave method:password in plain text
        if ":" in decoded:
            method, password = decoded.split(":", 1)
        if ":" in hostport:
            address, port_str = hostport.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                return None
    else:
        # legacy fully-encoded form: ss://base64(method:password@host:port)
        try:
            decoded = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("utf-8")
        except Exception:
            return None
        if "@" not in decoded or ":" not in decoded:
            return None
        userinfo, hostport = decoded.rsplit("@", 1)
        if ":" in userinfo:
            method, password = userinfo.split(":", 1)
        if ":" in hostport:
            address, port_str = hostport.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                return None

    if not (method and password and address and port):
        return None

    outbound = {
        "type": "shadowsocks",
        "tag": tag,
        "server": address,
        "server_port": port,
        "method": method,
        "password": password,
    }

    params = urllib.parse.parse_qs(query, keep_blank_values=True)
    plugin = params.get("plugin", [""])[0]
    if plugin:
        # e.g. "obfs-local;obfs=http;obfs-host=example.com" - sing-box wants
        # the plugin name and its options split apart. If sing-box wasn't
        # built with that plugin, this server will simply fail the real
        # connectivity check later and get filtered out like any dead node.
        parts = urllib.parse.unquote(plugin).split(";")
        outbound["plugin"] = parts[0]
        if len(parts) > 1:
            outbound["plugin_opts"] = ";".join(parts[1:])

    return outbound


def _parse_authority_uri(uri: str, scheme: str, index: int, default_port: int = 443):
    """Generic parser helper for URI-style protocols."""
    body = uri[len(scheme):]
    if "#" in body:
        body, remark = body.split("#", 1)
        remark = urllib.parse.unquote(remark)
    else:
        remark = f"{scheme[:-3]}-{index}"
    if "?" in body:
        authority, query = body.split("?", 1)
    else:
        authority, query = body, ""
    params = urllib.parse.parse_qs(query, keep_blank_values=True)
    if "/" in authority:
        authority = authority.split("/", 1)[0]
    try:
        parsed = urllib.parse.urlsplit("//" + authority)
        username = urllib.parse.unquote(parsed.username or "")
        password = urllib.parse.unquote(parsed.password or "")
        host = parsed.hostname or ""
        port = parsed.port or default_port
    except Exception:
        return None
    if not host:
        return None
    return host, port, username, password, params, remark


def _q(params, key, default=""):
    v = params.get(key)
    return v[0] if v else default


def _tls_from_params(params, host, default_enabled=True):
    insecure = _q(params, "insecure", _q(params, "allow_insecure", "0")) in ("1", "true", "True")
    sni = _q(params, "sni", _q(params, "peer", host))
    tls = {"enabled": bool(default_enabled), "server_name": sni, "insecure": insecure}
    alpn = _q(params, "alpn", "")
    if alpn:
        tls["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
    fp = _q(params, "fp", "")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    return tls


def parse_tuic_uri(uri: str, index: int):
    if not uri.startswith("tuic://"):
        return None
    parsed = _parse_authority_uri(uri, "tuic://", index, 443)
    if not parsed:
        return None
    host, port, uuid, password, params, remark = parsed
    # Common TUIC links use uuid:password@host:port.
    if not uuid:
        return None
    cc = _q(params, "congestion_control", _q(params, "cc", "cubic")).lower()
    if cc not in {"cubic", "new_reno", "bbr"}:
        cc = "cubic"
    relay = _q(params, "udp_relay_mode", "native").lower()
    if relay not in {"native", "quic"}:
        relay = "native"
    return {
        "type": "tuic", "tag": f"{index:02d}. {remark}".strip(),
        "server": host, "server_port": port, "uuid": uuid,
        "password": password, "congestion_control": cc,
        "udp_relay_mode": relay,
        "zero_rtt_handshake": _q(params, "zero_rtt", _q(params, "zero_rtt_handshake", "0")) in ("1", "true", "True"),
        "tls": _tls_from_params(params, host, True),
    }


def parse_shadowtls_uri(uri: str, index: int):
    if not uri.startswith("shadowtls://"):
        return None
    parsed = _parse_authority_uri(uri, "shadowtls://", index, 443)
    if not parsed:
        return None
    host, port, username, password, params, remark = parsed
    version = _q(params, "version", "3")
    try:
        version = int(version)
    except ValueError:
        version = 3
    if version not in (1, 2, 3):
        version = 3
    auth = password or username
    if version in (2, 3) and not auth:
        return None
    return {
        "type": "shadowtls", "tag": f"{index:02d}. {remark}".strip(),
        "server": host, "server_port": port, "version": version,
        **({"password": auth} if auth and version in (2, 3) else {}),
        "tls": _tls_from_params(params, host, True),
    }


def parse_anytls_uri(uri: str, index: int):
    if not uri.startswith("anytls://"):
        return None
    parsed = _parse_authority_uri(uri, "anytls://", index, 443)
    if not parsed:
        return None
    host, port, username, password, params, remark = parsed
    auth = password or username
    if not auth:
        return None
    return {
        "type": "anytls", "tag": f"{index:02d}. {remark}".strip(),
        "server": host, "server_port": port, "password": auth,
        "tls": _tls_from_params(params, host, True),
    }


def parse_naive_uri(uri: str, index: int):
    if not (uri.startswith("naive+https://") or uri.startswith("naive+quic://") or uri.startswith("naive://")):
        return None
    if uri.startswith("naive+quic://"):
        scheme = "naive+quic://"
        quic = True
    elif uri.startswith("naive+https://"):
        scheme = "naive+https://"
        quic = False
    else:
        scheme = "naive://"
        quic = False
    parsed = _parse_authority_uri(uri, scheme, index, 443)
    if not parsed:
        return None
    host, port, username, password, params, remark = parsed
    if not username:
        return None
    out = {
        "type": "naive", "tag": f"{index:02d}. {remark}".strip(),
        "server": host, "server_port": port, "username": username,
        "password": password, "quic": quic,
        "tls": _tls_from_params(params, host, True),
    }
    # NaiveProxy uses Chromium's own network stack: sing-box's uTLS/ALPN
    # options do not exist for it and would make the config invalid.
    out["tls"].pop("utls", None)
    out["tls"].pop("alpn", None)
    qcc = _q(params, "quic_congestion_control", "")
    if qcc in {"bbr", "bbr2", "cubic", "reno"}:
        out["quic_congestion_control"] = qcc
    return out


def parse_ssh_uri(uri: str, index: int):
    if not uri.startswith("ssh://"):
        return None
    parsed = _parse_authority_uri(uri, "ssh://", index, 22)
    if not parsed:
        return None
    host, port, username, password, params, remark = parsed
    if not username:
        return None
    out = {
        "type": "ssh", "tag": f"{index:02d}. {remark}".strip(),
        "server": host, "server_port": port, "user": username,
    }
    if password:
        out["password"] = password
    private_key = _q(params, "private_key", _q(params, "privateKey", ""))
    private_key_path = _q(params, "private_key_path", _q(params, "privateKeyPath", ""))
    if private_key:
        out["private_key"] = private_key
    if private_key_path:
        out["private_key_path"] = private_key_path
    return out


def parse_snell_uri(uri: str, index: int):
    """snell:// -> sing-box >= 1.14.0 "snell" outbound.

    There is no official Snell share-link standard; the de-facto form used by
    converters is  snell://PSK@host:port?version=4&obfs=http&obfs-host=x&reuse=1#name
    sing-box supports Snell v4 (v5 is wire-identical to v4, its QUIC proxy mode
    is intentionally not implemented) and v6. Snell v1-v3 and "tls" obfuscation
    are not supported by sing-box, so those links are skipped.
    """
    if not uri.startswith("snell://"):
        return None
    parsed = _parse_authority_uri(uri, "snell://", index, 443)
    if not parsed:
        return None
    host, port, username, password, params, remark = parsed
    psk = password or username
    if not psk:
        return None
    version = _q(params, "version", "4").strip()
    if version in ("4", "5"):
        version = 4
    elif version == "6":
        version = 6
    else:
        return None
    out = {
        "type": "snell", "tag": f"{index:02d}. {remark}".strip(),
        "server": host, "server_port": port, "version": version, "psk": psk,
    }
    userkey = _q(params, "userkey", "")
    if userkey:
        out["userkey"] = userkey
    if _q(params, "reuse", "0").lower() in ("1", "true"):
        out["reuse"] = True
    if version == 4:
        obfs = _q(params, "obfs", _q(params, "obfs_mode", "")).lower()
        if obfs == "http":
            out["obfs_mode"] = "http"
            obfs_host = _q(params, "obfs-host", _q(params, "obfs_host", _q(params, "host", "")))
            if obfs_host:
                out["obfs_host"] = obfs_host
        elif obfs not in ("", "none"):
            return None  # e.g. obfs=tls: not available in sing-box
    else:
        if not 12 <= len(psk.encode("utf-8")) <= 255:
            return None  # Snell v6 requires a 12..255 byte PSK
        mode = _q(params, "mode", "").lower()
        if mode in ("default", "unshaped", "unsafe-raw"):
            out["mode"] = mode
    return out


def parse_socks_uri(uri: str, index: int):
    scheme = next((s for s in ("socks5://", "socks4a://", "socks4://", "socks://") if uri.startswith(s)), None)
    if not scheme:
        return None
    parsed = _parse_authority_uri(uri, scheme, index, 1080)
    if not parsed:
        return None
    host, port, username, password, params, remark = parsed
    version = {"socks4://": "4", "socks4a://": "4a"}.get(scheme, _q(params, "version", "5"))
    if version not in {"4", "4a", "5"}:
        version = "5"
    out = {"type": "socks", "tag": f"{index:02d}. {remark}".strip(), "server": host, "server_port": port, "version": version}
    if username:
        out["username"] = username
    if password:
        out["password"] = password
    return out


def parse_http_proxy_uri(uri: str, index: int):
    if not (uri.startswith("http://") or uri.startswith("https://")):
        return None
    # This is an individual proxy URI, not a subscription URL. Subscription
    # fetches are handled before this parser is called.
    parsed = _parse_authority_uri(uri, "https://" if uri.startswith("https://") else "http://", index, 443 if uri.startswith("https://") else 8080)
    if not parsed:
        return None
    host, port, username, password, params, remark = parsed
    out = {"type": "http", "tag": f"{index:02d}. {remark}".strip(), "server": host, "server_port": port}
    if username:
        out["username"] = username
    if password:
        out["password"] = password
    if uri.startswith("https://") or _q(params, "tls", "0") in ("1", "true", "True"):
        out["tls"] = _tls_from_params(params, host, True)
    return out


def parse_proxy_uri(uri: str, index: int, extended: bool = False):
    """Dispatches to the right parser based on the link's scheme. Add more
    'elif uri.startswith(...)' branches here for other protocols later."""
    if uri.startswith("vless://"):
        return parse_vless_uri(uri, index, extended=extended)
    if uri.startswith("trojan://"):
        return parse_trojan_uri(uri, index)
    if uri.startswith("hysteria2://") or uri.startswith("hy2://"):
        return parse_hysteria2_uri(uri, index)
    if uri.startswith("hysteria://") or uri.startswith("hy://"):
        return parse_hysteria_uri(uri, index)
    if uri.startswith("warp://") or uri.startswith("wireguard://"):
        return parse_wireguard_uri(uri, index)
    if uri.startswith("vmess://"):
        return parse_vmess_uri(uri, index)
    if uri.startswith("ss://"):
        return parse_ss_uri(uri, index)
    if uri.startswith("tuic://"):
        return parse_tuic_uri(uri, index)
    if uri.startswith("shadowtls://"):
        return parse_shadowtls_uri(uri, index)
    if uri.startswith("anytls://"):
        return parse_anytls_uri(uri, index)
    if uri.startswith("naive+https://") or uri.startswith("naive+quic://") or uri.startswith("naive://"):
        return parse_naive_uri(uri, index)
    if uri.startswith("ssh://"):
        return parse_ssh_uri(uri, index)
    if uri.startswith("snell://"):
        return parse_snell_uri(uri, index)
    if uri.startswith(("socks://", "socks5://", "socks4://", "socks4a://")):
        return parse_socks_uri(uri, index)
    if uri.startswith("http://") or uri.startswith("https://"):
        return parse_http_proxy_uri(uri, index)
    return None


