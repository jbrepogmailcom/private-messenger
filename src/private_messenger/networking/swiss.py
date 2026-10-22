"""Pinned Swiss demo router and its operator's public queue-creation password."""

import html
import http.client
import re
import ssl
import urllib.parse
import urllib.request

from private_messenger.config import Server

PAGE = "https://urban-network.ch/services/simplex"
SERVER = "smp://LtowhzwGvh3lqlFvMqxCTPmZ_OzcwOq_NCsNG7ya1lc=@urban-network.dyndns.org:5224"
MAX_PAGE_SIZE = 256 * 1024


class SameOriginHTTPS(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urllib.parse.urlsplit(newurl)
        if url.scheme != "https" or url.netloc != "urban-network.ch":
            raise ValueError("unexpected operator website redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def public_router_password(page: str) -> bytes:
    """Accept only the descriptor matching the preconfigured router pin/host/port."""
    expected = Server.parse(SERVER)
    for match in re.finditer(r"smp://[^\s<>\"']+", html.unescape(page)):
        try:
            uri = urllib.parse.urlsplit(match[0])
            host = uri.hostname.split(",")[0] if uri.hostname else ""
            candidate = Server.parse(f"smp://{uri.username}@{host}:{uri.port or 5223}")
            password = uri.password.encode("utf-8") if uri.password else b""
            if candidate == expected and 1 <= len(password) <= 255:
                return password
        except ValueError:
            continue
    raise ValueError(
        "operator page has no matching pinned router descriptor; it may block Tor. "
        "Obtain the NEW password independently and configure servers URI --basic-auth-file PATH"
    )


def download_public_password(network=None) -> bytes:
    if network is not None and network.mode == "TOR":
        # Remote-DNS SOCKS socket, with no secondary direct HTTPS connection.
        host = "urban-network.ch"
        sock = network.connect(Server(host, 443, bytes(32)))
        try:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
                tls.sendall(
                    b"GET /services/simplex HTTP/1.1\r\nHost: urban-network.ch\r\n"
                    b"Connection: close\r\nAccept: text/html\r\n\r\n"
                )
                response = http.client.HTTPResponse(tls)
                response.begin()
                if response.status != 200:
                    raise ValueError("operator website did not return HTTPS 200")
                page = response.read(MAX_PAGE_SIZE + 1)
                if len(page) > MAX_PAGE_SIZE:
                    raise ValueError("operator page exceeds size limit")
                return public_router_password(page.decode("utf-8"))
        finally:
            sock.close()
    opener = urllib.request.build_opener(SameOriginHTTPS())
    # Fixed HTTPS URL, default CA validation, same-origin HTTPS redirects only.
    with opener.open(PAGE, timeout=20) as response:  # noqa: S310
        page = response.read(MAX_PAGE_SIZE + 1)
        if len(page) > MAX_PAGE_SIZE:
            raise ValueError("operator page exceeds size limit")
    return public_router_password(page.decode("utf-8"))
