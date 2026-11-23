#!/usr/bin/env python3
"""
BGMI ID Info API – Dynamic Region Detection (with built-in debug system)
Fetches username from rooter.gg.

DEBUG USAGE
-----------
  /api/bgmi?uid=<UID>&debug=1     -> normal result + full step-by-step trace
  /api/debug?uid=<UID>            -> trace + environment + connectivity checks
  /health                         -> quick liveness check

Env vars (optional):
  DEBUG_KEY  -> if set, debug endpoints need  &key=<DEBUG_KEY>
  LOG_LEVEL  -> DEBUG / INFO / WARNING (default INFO). Logs show in Vercel > Logs.
"""

import requests
import json
import time
import re
import os
import sys
import logging
import traceback
from urllib.parse import unquote
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------- Logging ----------
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("bgmi-api")

# ---------- Config ----------
CACHE_TTL = 300
USER_CACHE = {}
TOKEN_CACHE = {}  # site name -> {"token":..., "expires_at":...}

# Rooter ka naya store. Purana www.rooter.gg ab username endpoint pe 499 deta hai (debug se confirm),
# isliye hata diya. Zaroorat pade to yahan dobara dict add kar sakte ho (fallback apne aap kaam karega).
SITES = [
    {"name": "shop", "home": "https://shop.rooter.gg/product/bgmi-uc-purchase",
     "origin": "https://shop.rooter.gg", "referer": "https://shop.rooter.gg/"},
]
DEBUG_KEY = os.environ.get("DEBUG_KEY")

# Logged-in rooter account ka token (private use). Env var ROOTER_TOKEN set ho to wo pehle use hota hai.
# Token expire hone par (debug me 'exp_in_s' dikhta hai) rooterlogin.py se naya nikalke yahan badal do.
# NOTE: is repo ko PRIVATE rakho.
ROOTER_TOKEN_FALLBACK = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIxMDUyMTk1OTEsInNJZCI6ImNhYjdhNWZmLWE2MGUtNDMxOS04NzNmLTQ1M2Y1MDBjNDliNyIsInJvbGVzIjpbXSwiZGV2aWNlIjoid2ViIiwic2ZDcmVhdGVkQXQiOjE3OTU0MzMzMDgsImlzVmVyaWZpZWQiOnRydWUsInVzZXJSb2xlcyI6e30sImlhdCI6MTc5NTQzNTY4NiwiZXhwIjoxNzk5MzIzNjg2fQ.3DLegcekcXTTdO7eJC-oCrIwmTb5sY2cS_gxU-I49dQ"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


# ======================================================================
# Debug helpers
# ======================================================================
def snippet(text, n=300):
    """Short, single-line preview of a response body."""
    if text is None:
        return None
    text = str(text).replace("\n", " ").replace("\r", " ")
    return text[:n] + ("…" if len(text) > n else "")


def mask(token):
    """Never expose a full token in debug output."""
    if not token:
        return None
    return f"{token[:6]}…{token[-4:]} (len={len(token)})"


def jwt_claims(token):
    """JWT payload dict (verify nahi karte)."""
    try:
        import base64
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def jwt_info(token):
    """JWT payload se sirf expiry/keys nikalo (debug ke liye). Token verify nahi karte."""
    try:
        import base64
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        out = {"claims": sorted(data.keys())}
        now = time.time()
        if "exp" in data:
            out["exp_in_s"] = int(data["exp"] - now)
        if "iat" in data:
            out["age_s"] = int(now - data["iat"])
        return out
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def looks_blocked(resp):
    """Detect Cloudflare / bot-protection / rate-limit pages."""
    body = (resp.text or "")[:2000].lower()
    hints = []
    if resp.status_code in (403, 429, 503):
        hints.append(f"HTTP {resp.status_code}")
    if "cloudflare" in body or "cf-ray" in {k.lower() for k in resp.headers}:
        hints.append("cloudflare")
    if "captcha" in body or "just a moment" in body or "attention required" in body:
        hints.append("captcha/challenge page")
    return hints


class Trace:
    """Collects every step of a request so we can see exactly where it breaks."""

    def __init__(self):
        self.steps = []
        self.t0 = time.time()

    def add(self, step, ok, **info):
        entry = {
            "step": step,
            "ok": ok,
            "t_ms": int((time.time() - self.t0) * 1000),
        }
        entry.update({k: v for k, v in info.items() if v is not None})
        self.steps.append(entry)
        level = logging.INFO if ok else logging.WARNING
        log.log(level, "[%s] ok=%s %s", step, ok, json.dumps(info, default=str)[:500])

    def first_failure(self):
        for s in self.steps:
            if not s["ok"]:
                return s
        return None

    def to_dict(self):
        fail = self.first_failure()
        return {
            "total_ms": int((time.time() - self.t0) * 1000),
            "first_failure": {"step": fail["step"], "error": fail.get("error")} if fail else None,
            "steps": self.steps,
        }


# ======================================================================
# Token (rooter)
# ======================================================================
def extract_token(session):
    """Cookies me se accessToken dhundo. 'user_auth' pehle, phir baaki sab cookies."""
    names = ["user_auth"] + [n for n in session.cookies.keys() if n != "user_auth"]
    for name in names:
        raw = session.cookies.get(name)
        if not raw:
            continue
        try:
            data = json.loads(unquote(raw))
        except Exception:
            continue
        if isinstance(data, dict) and data.get("accessToken"):
            return data["accessToken"], name
    return None, None


def get_authorization_token(session, trace, site, force_refresh=False):
    n = site["name"]
    now = time.time()

    # Logged-in account ka token (Vercel env var ROOTER_TOKEN) — guest token reject ho raha ho to ye use hota hai
    env_token = (os.environ.get("ROOTER_TOKEN", "") or ROOTER_TOKEN_FALLBACK).strip()
    # Pura user_auth cookie value paste kar diya ho ({"accessToken":...} ya URL-encoded) to usme se token nikalo
    if env_token.startswith(("{", "%7B", "%7b")):
        try:
            env_token = json.loads(unquote(env_token)).get("accessToken", "") or ""
        except Exception:
            trace.add(f"{n}.token.env", False, error="ROOTER_TOKEN parse nahi hua (sirf accessToken ya poori user_auth cookie value daalo)")
            env_token = ""
    if env_token:
        trace.add(f"{n}.token.env", True, token=mask(env_token), jwt=jwt_info(env_token),
                  note="ROOTER_TOKEN env var use ho raha hai (guest token nahi)")
        return env_token

    cached = TOKEN_CACHE.get(n)
    if not force_refresh and cached and cached["expires_at"] > now:
        trace.add(f"{n}.token.cache", True, note="using cached token",
                  token=mask(cached["token"]), expires_in_s=int(cached["expires_at"] - now),
                  jwt=jwt_info(cached["token"]))
        return cached["token"]

    try:
        headers = {
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        resp = session.get(site["home"], headers=headers, timeout=10)
        blocked = looks_blocked(resp)
        trace.add(f"{n}.token.request", resp.status_code == 200 and not blocked,
                  url=site["home"], status=resp.status_code, final_url=resp.url,
                  cookies_received=sorted(session.cookies.keys()),
                  blocked_hints=blocked or None,
                  error=(f"{n}: request block hui: {blocked}" if blocked else None),
                  body_preview=None if resp.status_code == 200 else snippet(resp.text))

        token, cookie_name = extract_token(session)
        if not token:
            trace.add(f"{n}.token.cookie", False,
                      error=f"{n}: kisi cookie me accessToken nahi mila "
                            f"(server IP block ya site ne guest cookie dena band kiya)",
                      cookies_received=sorted(session.cookies.keys()))
            return None

        info = jwt_info(token)
        ttl = 600  # max 10 min cache (rooter token jaldi invalid ho jata hai)
        if isinstance(info.get("exp_in_s"), int):
            ttl = max(0, min(ttl, info["exp_in_s"] - 60))
        TOKEN_CACHE[n] = {"token": token, "expires_at": now + ttl,
                          "client_id": session.cookies.get("client_id")}
        trace.add(f"{n}.token.parse", True, token=mask(token), cookie=cookie_name,
                  jwt=info, cache_ttl_s=ttl)
        return token

    except Exception as e:
        trace.add(f"{n}.token.exception", False, error=f"{type(e).__name__}: {e}")
        log.error("Token fetch error (%s): %s", n, e)
        return None


# ======================================================================
# Username (rooter)
# ======================================================================
def api_error(resp):
    """Rooter ke error body se asli message nikalo."""
    try:
        j = resp.json()
        err = j.get("error") or j.get("data") or {}
        return (f"rooter error: {j.get('message')} | statusCode={err.get('statusCode')} | "
                f"{err.get('developerMessage') or j.get('developerMessage')}")
    except Exception:
        return f"HTTP {resp.status_code}"


def try_username(uid, trace, site, session, token, device_id, source):
    """Ek Device-Id ke saath username call. Return (username, auth_failed)."""
    n = site["name"]
    url = f"https://bazaar.rooter.io/order/getUnipinUsername?gameCode=BGMI_IN&id={uid}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Device-Type": "web",
        "App-Version": "1.0.0",
        "Device-Id": device_id,
        "User-Agent": UA,
        "Accept": "application/json",
        "Origin": site["origin"],
        "Referer": site["referer"],
    }

    def call():
        return session.get(url, headers=headers, timeout=15)

    try:
        resp = call()
        # 499 / 5xx = rooter ka upstream error, ek baar retry
        if resp.status_code == 499 or resp.status_code >= 500:
            trace.add(f"{n}.username.upstream_error", False, device_source=source,
                      status=resp.status_code, error=api_error(resp))
            time.sleep(1.5)
            resp = call()

        trace.add(f"{n}.username.request", resp.status_code == 200, url=url,
                  device_source=source, status=resp.status_code,
                  content_type=resp.headers.get("Content-Type"),
                  blocked_hints=looks_blocked(resp) or None,
                  error=None if resp.status_code == 200 else api_error(resp),
                  body_preview=snippet(resp.text))

        if resp.status_code in (401, 403):
            return None, True

        try:
            data = resp.json()
        except Exception as e:
            trace.add(f"{n}.username.json", False,
                      error=f"Response JSON nahi hai: {e}", body_preview=snippet(resp.text))
            return None, False

        transaction = data.get("transaction") if isinstance(data, dict) else None
        if transaction == "SUCCESS":
            username = (data.get("unipinRes") or {}).get("username")
            trace.add(f"{n}.username.result", bool(username), username=username,
                      device_source=source,
                      error=None if username else "SUCCESS aaya par 'unipinRes.username' empty hai",
                      raw=None if username else snippet(json.dumps(data), 400))
            return username, False

        err = ((data.get("unipinRes") or {}).get("error") or data.get("error") or {}) if isinstance(data, dict) else {}
        if not isinstance(err, dict):
            err = {}
        auth_failed = (err.get("code") == 703
                       or "authentication" in str(err.get("message", "")).lower())
        trace.add(f"{n}.username.result", False, device_source=source,
                  error=f"{n}: SUCCESS nahi mila (transaction={transaction!r}, "
                        f"rooter_error={err.get('message')!r}, code={err.get('code')})",
                  auth_failed=auth_failed,
                  raw=snippet(json.dumps(data), 400))
        return None, auth_failed
    except Exception as e:
        trace.add(f"{n}.username.exception", False, error=f"{type(e).__name__}: {e}")
        log.error("Username fetch error (%s) for %s: %s", n, uid, e)
        return None, False


def fetch_username_from_site(uid, trace, site, force_refresh=False):
    n = site["name"]
    session = requests.Session()
    token = get_authorization_token(session, trace, site, force_refresh=force_refresh)
    if not token:
        return None

    # "Authentication not match" (703) aksar tab aata hai jab Device-Id token ke 'device' claim se
    # match nahi karta. Isliye alag-alag Device-Id try karte hain.
    client_id = session.cookies.get("client_id") or (TOKEN_CACHE.get(n) or {}).get("client_id")
    device_claim = jwt_claims(token).get("device")
    device_val = None
    if isinstance(device_claim, str):
        device_val = device_claim
    elif isinstance(device_claim, dict):
        for k in ("id", "deviceId", "device_id", "uuid"):
            if isinstance(device_claim.get(k), str):
                device_val = device_claim[k]
                break

    candidates = []
    for label, val in (("jwt.device", device_val), ("cookie.client_id", client_id),
                       ("static", "api-service")):
        if val and val not in [c[1] for c in candidates]:
            candidates.append((label, val))

    trace.add(f"{n}.device_candidates", True,
              device_claim_type=type(device_claim).__name__,
              device_claim_keys=sorted(device_claim.keys()) if isinstance(device_claim, dict) else None,
              device_claim_preview=snippet(device_claim, 10) if device_claim is not None else None,
              client_id_preview=snippet(client_id, 10) if client_id else None,
              device_claim_equals_client_id=bool(device_val and client_id and device_val == client_id),
              will_try=[c[0] for c in candidates])

    any_auth_failed = False
    for label, device_id in candidates:
        username, auth_failed = try_username(uid, trace, site, session, token, device_id, label)
        if username:
            trace.add(f"{n}.device_id_worked", True, device_source=label)
            return username
        any_auth_failed = any_auth_failed or auth_failed
        if not auth_failed:
            return None  # auth ka masla nahi hai, doosra Device-Id try karne ka fayda nahi

    # Sab Device-Id me auth fail -> fresh token se ek baar aur
    if any_auth_failed and not force_refresh:
        trace.add(f"{n}.username.auth_retry", True,
                  note="sab Device-Id pe auth fail, fresh token se ek baar retry")
        TOKEN_CACHE.pop(n, None)
        return fetch_username_from_site(uid, trace, site, force_refresh=True)
    return None


def fetch_username(uid, trace):
    """Sab SITES try karo. Jo pehle chale uska username return. probe=1 me sab try hote hain."""
    found = None
    for site in SITES:
        username = fetch_username_from_site(uid, trace, site)
        if username:
            trace.add("username.source", True, site=site["name"], username=username)
            found = found or username
            if not getattr(trace, "try_all", False):
                break
    return found


# ======================================================================
# Get Player Info
# ======================================================================
def get_player_info(uid, trace, use_cache=True):
    now = time.time()
    if use_cache and uid in USER_CACHE and now - USER_CACHE[uid]["timestamp"] < CACHE_TTL:
        trace.add("cache.hit", True, uid=uid)
        return USER_CACHE[uid]["data"]
    trace.add("cache.miss", True, uid=uid)

    username = fetch_username(uid, trace)

    if not username:
        # Fail ko cache NAHI karte, warna 5 minute tak galat "Unknown" milta rahega
        fail = trace.first_failure()
        return {
            "success": False,
            "uid": uid,
            "error": "Username fetch nahi ho paya",
            "reason": fail.get("error") if fail else "unknown",
            "failed_step": fail["step"] if fail else None,
            "hint": "Debug ke liye URL me &debug=1 lagao ya /api/debug?uid=<UID> kholo",
        }

    result = {
        "success": True,
        "username": username,
        "uid": uid,
        "server": "BGMI",
        "region": "India",  # BGMI_IN = India server
        
    }
    USER_CACHE[uid] = {"data": result, "timestamp": now}
    return result


# ======================================================================
# Debug access control
# ======================================================================
def debug_allowed():
    if not DEBUG_KEY:
        return True
    return request.args.get("key") == DEBUG_KEY


def check_host(url):
    """Connectivity check for one host."""
    t = time.time()
    try:
        r = requests.get(url, headers={"User-Agent": UA}, timeout=8)
        return {"url": url, "reachable": True, "status": r.status_code,
                "ms": int((time.time() - t) * 1000),
                "blocked_hints": looks_blocked(r) or None}
    except Exception as e:
        return {"url": url, "reachable": False, "ms": int((time.time() - t) * 1000),
                "error": f"{type(e).__name__}: {e}"}


# ======================================================================
# Routes
# ======================================================================
@app.route("/")
def home():
    return jsonify({
        "service": "BGMI ID Info API",
        "endpoint": "/api/bgmi?uid=<UID>",
        "example": "/api/bgmi?uid=5120321397",
        "debug": "/api/debug?uid=<UID>  or  /api/bgmi?uid=<UID>&debug=1",
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": int(time.time())})


@app.route("/api/bgmi", methods=["GET"])
def bgmi_info():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"success": False, "error": "Missing 'uid' parameter"}), 400
    if not uid.isdigit():
        return jsonify({"success": False, "error": "UID must be numeric"}), 400

    want_debug = request.args.get("debug") in ("1", "true", "yes")
    if want_debug and not debug_allowed():
        return jsonify({"success": False, "error": "Invalid or missing debug key"}), 403

    trace = Trace()
    data = get_player_info(uid, trace, use_cache=not want_debug)
    status = 200 if data.get("success") else 502

    if want_debug:
        data = dict(data)
        data["debug"] = trace.to_dict()
    return jsonify(data), status


@app.route("/api/debug", methods=["GET"])
def debug_endpoint():
    if not debug_allowed():
        return jsonify({"success": False, "error": "Invalid or missing debug key"}), 403

    uid = request.args.get("uid", "5120321397")
    if not uid.isdigit():
        return jsonify({"success": False, "error": "UID must be numeric"}), 400

    trace = Trace()
    trace.try_all = request.args.get("probe", "1") != "0"  # debug me default sab sites try
    result = get_player_info(uid, trace, use_cache=False)

    return jsonify({
        "uid": uid,
        "result": result,
        "trace": trace.to_dict(),
        "environment": {
            "python": sys.version.split()[0],
            "vercel": bool(os.environ.get("VERCEL")),
            "vercel_region": os.environ.get("VERCEL_REGION"),
            "requests": requests.__version__,
            "flask_import_ok": True,
            "debug_key_set": bool(DEBUG_KEY),
        },
        "cache": {
            "tokens": {k: {"token": mask(v["token"]),
                           "expires_in_s": max(0, int(v["expires_at"] - time.time()))}
                       for k, v in TOKEN_CACHE.items()},
            "users_cached": len(USER_CACHE),
        },
        "connectivity": [
            check_host("https://shop.rooter.gg/"),
            check_host("https://www.rooter.gg/"),
            check_host("https://bazaar.rooter.io/"),
        ],
    }), 200


@app.errorhandler(Exception)
def handle_exception(e):
    """Koi bhi unexpected crash — JSON me saaf error, traceback sirf debug mode me."""
    log.exception("Unhandled error")
    body = {"success": False, "error": f"{type(e).__name__}: {e}"}
    if request.args.get("debug") in ("1", "true", "yes") and debug_allowed():
        body["traceback"] = traceback.format_exc()
    return jsonify(body), 500


# ---------- Local Development ----------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=False)
