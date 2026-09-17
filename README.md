# v2tun

`v2tun` exposes local HTTP and SOCKS5 proxies backed by Xray-core's VLESS outbound. The SOCKS5 proxy supports TCP connections and UDP relay. It accepts a single `vless://` link or an HTTP(S) subscription containing newline-separated VLESS links, either plain text or base64 encoded. It selects the first supported link in the subscription. Supported transports are RAW/TCP and XHTTP with TLS or Reality.

## Run

```sh
./v2tun -c '<your_vless_link_here>' -p 12334 -s 12335 -e exceptions.txt
```

The HTTP proxy listens on `127.0.0.1:12334` by default. Set your application's HTTP and HTTPS proxy to `http://127.0.0.1:12334`. For example:

```sh
export http_proxy=http://127.0.0.1:12334
export https_proxy=$http_proxy
```

The SOCKS5 proxy listens on `127.0.0.1:12335` by default. Set applications that need UDP to use `socks5://127.0.0.1:12335` and enable SOCKS5 UDP support in the application. SOCKS5 UDP uses a TCP `UDP ASSOCIATE` control connection and a UDP relay on the SOCKS5 port; applications that only support HTTP proxies or SOCKS5 TCP will not send UDP through it. Both listeners accept local connections only. `-p` changes the HTTP port and `-s` changes the SOCKS5 TCP/UDP port; the ports must differ.

`-r` sets the subscription refresh interval in hours (default `2`, e.g. `-r 0.5` for 30 minutes). The current node stays active if fetching or parsing a refresh fails. When the selected node changes, the local listener restarts briefly. A direct `vless://` link is not refreshed.

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
