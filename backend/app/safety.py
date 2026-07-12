from urllib.parse import urlparse
import ipaddress, socket
from fastapi import HTTPException
BLOCKED_HOSTS={"localhost","127.0.0.1","0.0.0.0","::1"}
def validate_public_http_url(url:str)->None:
    p=urlparse(url)
    if p.scheme not in {"http","https"} or not p.netloc:
        raise HTTPException(400,"Only public http/https URLs are allowed in Phase 1.")
    host=(p.hostname or '').lower().strip('.')
    if host in BLOCKED_HOSTS or host.endswith('.local') or host.endswith('.internal'):
        raise HTTPException(400,"Private/internal targets are blocked by default safety policy.")
    try:
        ip=ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise HTTPException(400,"Private/reserved IP targets are blocked by default safety policy.")
    except ValueError:
        try:
            infos=socket.getaddrinfo(host,None,proto=socket.IPPROTO_TCP)[:6]
            for info in infos:
                ip=ipaddress.ip_address(info[4][0])
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                    raise HTTPException(400,"Target resolves to a private/reserved address and is blocked.")
        except HTTPException: raise
        except Exception: pass
