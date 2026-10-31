"""Network access for the staging host: HTTPS only (or file:// local media),
certificate verification on, redirects may not downgrade, hard size caps.
A content-addressed cache avoids re-downloading packages whose hash is known
from signed metadata; unsigned or not-yet-verified files are never cached.
"""
import hashlib
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from .report import die

ALLOW_HTTP = False
CACHE_DIR = None


class _HTTPSOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        scheme = urllib.parse.urlsplit(newurl).scheme
        if scheme != "https" and not (ALLOW_HTTP and scheme == "http"):
            raise urllib.error.URLError(f"refusing redirect to {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HTTPSOnlyRedirects())


class NotFound(Exception):
    pass


def fetch(url, limit, sha256=None, what=None):
    """Fetch url (at most `limit` bytes). With sha256, the cache is consulted
    and the result is checked (the caller still re-checks against signed data)."""
    if sha256 and CACHE_DIR:
        cp = os.path.join(CACHE_DIR, sha256[:2], sha256)
        if os.path.exists(cp):
            with open(cp, "rb") as f:
                data = f.read()
            if hashlib.sha256(data).hexdigest() == sha256:
                return data
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "file":
        path = urllib.parse.unquote(parts.path)
        if not os.path.exists(path):
            raise NotFound(url)
        with open(path, "rb") as f:
            data = f.read(limit + 1)
    elif parts.scheme == "https" or (ALLOW_HTTP and parts.scheme == "http"):
        req = urllib.request.Request(url, headers={"User-Agent": "pmtrust/2"})
        for attempt in range(4):
            try:
                with _OPENER.open(req, timeout=180) as resp:
                    data = resp.read(limit + 1)
                break
            except urllib.error.HTTPError as e:
                if e.code in (404, 410):
                    raise NotFound(url) from e
                if e.code < 500 or attempt == 3:
                    die(f"{url}: HTTP {e.code}")
            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as e:
                if attempt == 3 or "refusing redirect" in str(e):
                    die(f"{url}: {getattr(e, 'reason', e)}")
            time.sleep(2 * (attempt + 1))
    else:
        die(f"refusing URL {url}: only https:// and file:// (--allow-http permits http://)")
    if len(data) > limit:
        die(f"{what or url}: response exceeds the {limit}-byte limit")
    if sha256 and CACHE_DIR and hashlib.sha256(data).hexdigest() == sha256:
        cp = os.path.join(CACHE_DIR, sha256[:2], sha256)
        os.makedirs(os.path.dirname(cp), exist_ok=True)
        tmp = cp + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, cp)
    return data


def join(base, *parts):
    return "/".join([base.rstrip("/")] + [p.strip("/") for p in parts])
