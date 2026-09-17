# v2tun

`v2tun` exposes local HTTP and SOCKS5 proxies backed by Xray-core's VLESS outbound. The SOCKS5 proxy supports TCP connections and UDP relay. It accepts a single `vless://` link or an HTTP(S) subscription containing newline-separated VLESS links, either plain text or base64 encoded. It selects the first supported link in the subscription. Supported transports are RAW/TCP and XHTTP with TLS or Reality.

## Run

```sh
./v2tun -c '<your_vless_link_here>' -s 12335 -f chrome -e exceptions.txt
```

The HTTP proxy is disabled unless `-p` is supplied. To enable it, use `-p 12334` and set your application's HTTP and HTTPS proxy to `http://127.0.0.1:12334`. For example:

```sh
export http_proxy=http://127.0.0.1:12334
export https_proxy=$http_proxy
```

The SOCKS5 proxy listens on `127.0.0.1:12335` by default. Set applications that need UDP to use `socks5://127.0.0.1:12335` and enable SOCKS5 UDP support in the application. SOCKS5 UDP uses a TCP `UDP ASSOCIATE` control connection and a UDP relay on the SOCKS5 port; applications that only support HTTP proxies or SOCKS5 TCP will not send UDP through it. Listeners accept local connections only. `-s` changes the SOCKS5 TCP/UDP port; if HTTP is enabled, its port must differ.

`-f` overrides the VLESS link's `fp` setting. Available values are `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `360`, `qq`, `random`, `randomized`, and `randomizednoalpn`. `random` selects one of Xray's modern fingerprints once when the program starts. `randomized` uses Xray's randomized TLS fingerprint. If `-f` is omitted, the link's `fp` is used; Reality defaults to `chrome` when neither is set.

`-r` sets the subscription refresh interval in hours (default `2`, e.g. `-r 0.5` for 30 minutes). The current node stays active if fetching or parsing a refresh fails. When the selected node changes, the local listener restarts briefly. A direct `vless://` link is not refreshed.

For subscription URLs, v2tun sends `User-Agent: V2Tun/1.0`, `x-device-os`, `x-device-model` (the host name), and `x-hwid` on each fetch. The HWID is a random, stable installation identifier saved in the user's config directory at `v2tun/hwid`; keeping that file preserves the identity. It is not derived from hardware serial numbers. These headers identify the client to Remnawave when it serves the subscription. Direct `vless://` links make no subscription request, and the VLESS connection itself has no field for Remnawave client name, OS, or HWID.

`-e` names an optional UTF-8 exceptions file, one entry per line. A normal domain such as `vk.com` matches that domain and its subdomains. A leading-dot zone such as `.ru` matches domains ending in `.ru`. Empty lines and `#` comments are ignored. Exception destinations connect directly; all other destinations use VLESS. Domain exceptions also apply to SOCKS5 UDP requests that carry a domain name. Connection access logs appear on stdout. The HTTP proxy supports HTTP requests and HTTPS `CONNECT` over TCP; use SOCKS5 for UDP. UDP forwarding also requires support from the selected VLESS server.

## Build

Requires Go 1.26 or newer. All dependencies are recorded in `go.mod` and `go.sum`. CGO is disabled; no C compiler or C library is needed.

Windows PowerShell (development):

```powershell
$env:CGO_ENABLED = '0'
go build -trimpath -o v2tun.exe .
```

Linux ARM64, including Alpine, from any Go-supported development host:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o v2tun .
```

Linux AMD64:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o v2tun .
```

When building on Alpine itself, `CGO_ENABLED=0 go build -trimpath -o v2tun .` uses the host architecture. Copy only the resulting binary and your exceptions file to the target. No separate Xray executable is needed.

The subscription URL can contain a credential, so avoid publishing it or including it in shared logs. `v2tun` never prints the URL or VLESS user ID. Subscription retrieval requires a valid HTTPS certificate; certificate verification is enabled.
