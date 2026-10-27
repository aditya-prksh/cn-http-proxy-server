# HTTP Proxy Server — Computer Networks Mini-Project

A teaching/demo HTTP forward proxy written in C for Linux/WSL. It demonstrates TCP sockets, HTTP request parsing and forwarding, concurrent clients using pthreads, a bounded in-memory GET response cache, destination blocklisting, logging, error responses, timeouts, and request timing. It supports HTTP `GET`, `HEAD`, and `CONNECT` tunneling for HTTPS clients.

## Build and run (Ubuntu/WSL)

```bash
sudo apt update
sudo apt install build-essential curl
make
./proxy_server                 # listens on 127.0.0.1:8888
```

Optional custom port: `./proxy_server 8890`.

## Test

Keep the server running in one terminal. In a second Ubuntu/WSL terminal, run:

```bash
curl -v -x http://127.0.0.1:8888 http://example.com/
curl -v -x http://127.0.0.1:8888 http://blocked.example/
bash tests/smoke_test.sh
```

The blocklist includes `blocked.example` as a demo rule. Expected results: ordinary HTTP forwarding receives a destination response; blocked host returns `403 Forbidden`. Repeated successful GETs may be served from the in-memory cache; look for `Cache HIT` in server output / `proxy.log`.

For HTTPS CONNECT smoke testing (if outbound network access is available):

```bash
curl -v -x http://127.0.0.1:8888 https://example.com/
```

## Implementation scope and limitations

- Handles one request per client connection and closes the connection afterward.
- Supports `GET`, `HEAD`, and `CONNECT`; other methods receive `501 Not Implemented`.
- Does not implement a full RFC-compliant proxy: request bodies for methods such as POST are intentionally unsupported; cache is in-memory, bounded, and has no expiry/HTTP cache-control semantics; no authentication or configurable ACL file; DNS/IP-based SSRF protections and IPv6 CONNECT authority handling should be reviewed before any non-local deployment.
- Binds only to `127.0.0.1` by default, which is appropriate for local demos and avoids exposing an open proxy on the LAN.
- This is an educational project, not production proxy software.

## Requirement evidence checklist

- [ ] Build cleanly with `make`.
- [ ] HTTP forwarding returns an upstream response.
- [ ] Blocklist test returns `403`.
- [ ] Repeated GET produces a cache hit in server logs.
- [ ] Multiple concurrent requests complete.
- [ ] Invalid request produces `400`; unsupported method produces `501`.
- [ ] Timeout / unreachable upstream behavior is documented.
- [ ] Record actual performance measurements for cache miss vs hit and concurrent clients.
- [ ] Commit work progressively and include the group's real contributions and AI-use declaration in the report.
