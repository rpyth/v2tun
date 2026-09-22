package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

const fingerprintOptions = "chrome, firefox, safari, ios, android, edge, 360, qq, random, randomized, randomizednoalpn"

type clientInfo struct {
	HWID, OS, Model string
}

type node struct {
	Name, Address, ID, Encryption, Flow, Network, Security string
	SNI, Fingerprint, PublicKey, ShortID, SpiderX          string
	Path, Host, Mode, ALPN                                 string
	Extra                                                  json.RawMessage
	Port                                                   int
}

func main() {
	source := flag.String("c", "", "subscription URL or vless:// URL")
	index := flag.Int("i", 0, "VLESS endpoint number (zero-based)")
	port := flag.Int("p", 0, "local HTTP proxy port (disabled unless specified)")
	socksPort := flag.Int("s", 12335, "local SOCKS5 proxy port (TCP and UDP)")
	fingerprint := flag.String("f", "", "VLESS TLS fingerprint override ("+fingerprintOptions+"); default: link fp")
	exceptions := flag.String("e", "", "file containing direct-connect domains or zones")
	refresh := flag.Float64("r", 2, "subscription refresh interval in hours")
	flag.Parse()
	if *source == "" || *index < 0 || *port < 0 || *port > 65535 || *socksPort < 1 || *socksPort > 65535 || (*port != 0 && *port == *socksPort) || *refresh <= 0 || !validFingerprint(*fingerprint) {
		flag.Usage()
		os.Exit(2)
	}
	domains, err := readExceptions(*exceptions)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var client clientInfo
	if !strings.HasPrefix(strings.ToLower(*source), "vless://") {
		client, err = deviceInfo()
		if err != nil {
			log.Fatalf("device identity: %v", err)
		}
	}
	n, err := loadNode(ctx, *source, client, *index)
	if err != nil {
		log.Fatal(err)
	}
	if *fingerprint != "" {
		n.Fingerprint = *fingerprint
	}
	if !validFingerprint(n.Fingerprint) {
		log.Fatalf("unsupported fingerprint %q (choose: %s)", n.Fingerprint, fingerprintOptions)
	}
	server, err := start(n, *port, *socksPort, domains)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { server.Close() }()
	if *port != 0 {
		log.Printf("HTTP proxy listening on 127.0.0.1:%d", *port)
	}
	log.Printf("SOCKS5 proxy (TCP/UDP) on 127.0.0.1:%d; selected %q (%s:%d)", *socksPort, n.Name, n.Address, n.Port)
	if strings.HasPrefix(strings.ToLower(*source), "vless://") {
		<-ctx.Done()
		return
	}
	ticker := time.NewTicker(time.Duration(*refresh * float64(time.Hour)))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			updated, err := loadNode(ctx, *source, client, *index)
			if err != nil {
				log.Printf("subscription refresh failed; keeping current node: %v", err)
				continue
			}
			if *fingerprint != "" {
				updated.Fingerprint = *fingerprint
			}
			if !validFingerprint(updated.Fingerprint) {
				log.Printf("subscription refresh has unsupported fingerprint %q; keeping current node", updated.Fingerprint)
				continue
			}
			if sameNode(n, updated) {
				log.Printf("subscription refreshed; node unchanged")
				continue
			}
			// Xray owns the listening socket. Close the old instance before binding the new one.
			server.Close()
			server, err = start(updated, *port, *socksPort, domains)
			if err != nil {
				log.Printf("new node failed: %v; restoring previous node", err)
				server, err = start(n, *port, *socksPort, domains)
				if err != nil {
					log.Fatalf("could not restore proxy: %v", err)
				}
				continue
			}
			n = updated
			log.Printf("subscription switched to %q (%s:%d)", n.Name, n.Address, n.Port)
		}
	}
}

func sameNode(a, b node) bool {
	a.Name, b.Name = "", ""
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func loadNode(ctx context.Context, source string, info clientInfo, index int) (node, error) {
	if strings.HasPrefix(strings.ToLower(source), "vless://") {
		if index != 0 {
			return node{}, errors.New("a direct VLESS link only has endpoint 0")
		}
		return parseNode(source)
	}
	u, err := url.Parse(source)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return node{}, errors.New("-c must be an HTTP(S) subscription URL or vless:// URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return node{}, err
	}
	if info.HWID != "" {
		req.Header.Set("User-Agent", "V2Tun/1.0")
		req.Header.Set("x-hwid", info.HWID)
		req.Header.Set("x-device-os", info.OS)
		if info.Model != "" {
			req.Header.Set("x-device-model", info.Model)
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return node{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return node{}, fmt.Errorf("subscription returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20+1))
	if err != nil {
		return node{}, err
	}
	if len(data) > 8<<20 {
		return node{}, errors.New("subscription exceeds 8 MiB")
	}
	nodes, err := parseSubscription(data)
	if err != nil {
		return node{}, err
	}
	fmt.Println("Available VLESS endpoints:")
	for i, n := range nodes {
		mark := " "
		if i == index {
			mark = "x"
		}
		fmt.Printf("[%s] %d: %s\n", mark, i, n.Name)
	}
	if index < 0 || index >= len(nodes) {
		return node{}, fmt.Errorf("VLESS endpoint index %d out of range (available: 0-%d)", index, len(nodes)-1)
	}
	return nodes[index], nil
}

func validFingerprint(name string) bool {
	if name == "" {
		return true
	}
	switch name {
	case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "randomizednoalpn":
		return xraytls.GetFingerprint(name) != nil
	}
	return false
}

func deviceInfo() (clientInfo, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return clientInfo{}, err
	}
	path := filepath.Join(dir, "v2tun", "hwid")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return clientInfo{}, err
		}
		var id [16]byte
		if _, err = rand.Read(id[:]); err != nil {
			return clientInfo{}, err
		}
		data = []byte(hex.EncodeToString(id[:]))
		file, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if os.IsExist(createErr) {
			data, err = os.ReadFile(path)
			if err != nil {
				return clientInfo{}, err
			}
		} else if createErr != nil {
			return clientInfo{}, createErr
		} else {
			_, err = file.Write(data)
			closeErr := file.Close()
			if err != nil {
				return clientInfo{}, err
			}
			if closeErr != nil {
				return clientInfo{}, closeErr
			}
		}
	} else if err != nil {
		return clientInfo{}, err
	}
	hwid := strings.TrimSpace(string(data))
	if len(hwid) != 32 {
		return clientInfo{}, fmt.Errorf("invalid HWID in %s", path)
	}
	if _, err = hex.DecodeString(hwid); err != nil {
		return clientInfo{}, fmt.Errorf("invalid HWID in %s: %w", path, err)
	}
	osName := map[string]string{"windows": "Windows", "darwin": "macOS", "linux": "Linux"}[runtime.GOOS]
	if osName == "" {
		osName = runtime.GOOS
	}
	hostname, _ := os.Hostname()
	return clientInfo{HWID: hwid, OS: osName, Model: hostname}, nil
}

func parseSubscription(data []byte) ([]node, error) {
	s := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	if !strings.Contains(strings.ToLower(s), "vless://") {
		compact := strings.Join(strings.Fields(s), "")
		var decoded []byte
		var err error
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			decoded, err = enc.DecodeString(compact)
			if err == nil {
				break
			}
		}
		if err != nil {
			return nil, errors.New("subscription is neither VLESS links nor base64-encoded VLESS links")
		}
		s = string(decoded)
	}
	var firstErr error
	var nodes []node
	for _, line := range strings.Fields(s) {
		if !strings.HasPrefix(strings.ToLower(line), "vless://") {
			continue
		}
		n, err := parseNode(line)
		if err == nil {
			nodes = append(nodes, n)
			continue
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if len(nodes) > 0 {
		return nodes, nil
	}
	if firstErr != nil {
		return nil, fmt.Errorf("no usable VLESS node: %w", firstErr)
	}
	return nil, errors.New("subscription contains no VLESS links")
}

func parseNode(link string) (node, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil {
		return node{}, err
	}
	if !strings.EqualFold(u.Scheme, "vless") || u.User == nil || u.Hostname() == "" {
		return node{}, errors.New("invalid VLESS URL")
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil || p < 1 || p > 65535 {
		return node{}, errors.New("invalid VLESS server port")
	}
	q := u.Query()
	n := node{Name: u.Fragment, Address: u.Hostname(), Port: p, ID: u.User.Username(), Encryption: q.Get("encryption"), Flow: q.Get("flow"), Network: strings.ToLower(q.Get("type")), Security: strings.ToLower(q.Get("security")), SNI: q.Get("sni"), Fingerprint: q.Get("fp"), PublicKey: q.Get("pbk"), ShortID: q.Get("sid"), SpiderX: q.Get("spx"), Path: q.Get("path"), Host: q.Get("host"), Mode: q.Get("mode"), ALPN: q.Get("alpn")}
	if n.ID == "" {
		return node{}, errors.New("VLESS user ID is empty")
	}
	if n.Encryption == "" {
		n.Encryption = "none"
	}
	if n.Network == "" || n.Network == "tcp" {
		n.Network = "raw"
	}
	if n.Security == "" {
		n.Security = "none"
	}
	if n.Security != "reality" && n.Security != "tls" {
		return node{}, fmt.Errorf("unsupported security %q", n.Security)
	}
	if n.Network != "raw" && n.Network != "xhttp" {
		return node{}, fmt.Errorf("unsupported transport %q", n.Network)
	}
	if n.Network == "xhttp" && n.Path == "" {
		n.Path = "/"
	}
	if n.Security == "reality" && (n.PublicKey == "" || n.SNI == "") {
		return node{}, errors.New("Reality requires pbk and sni")
	}
	if extra := q.Get("extra"); extra != "" {
		if !json.Valid([]byte(extra)) {
			return node{}, errors.New("invalid XHTTP extra JSON")
		}
		n.Extra = json.RawMessage(extra)
	}
	if n.Name == "" {
		n.Name = net.JoinHostPort(n.Address, strconv.Itoa(n.Port))
	}
	return n, nil
}

func readExceptions(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result []string
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.ToLower(strings.TrimSpace(strings.SplitN(line, "#", 2)[0]))
		line = strings.TrimSuffix(line, ".")
		if line == "" {
			continue
		}
		if strings.ContainsAny(line, " /:*@") {
			return nil, fmt.Errorf("invalid exception on line %d", i+1)
		}
		if strings.HasPrefix(line, ".") {
			if len(line) < 3 {
				return nil, fmt.Errorf("invalid domain zone on line %d", i+1)
			}
			result = append(result, "regexp:"+strings.ReplaceAll(line, ".", "\\.")+"$")
		} else {
			result = append(result, "domain:"+line)
		}
	}
	return result, nil
}

func start(n node, port, socksPort int, exceptions []string) (*core.Instance, error) {
	stream := map[string]any{"network": n.Network, "security": n.Security}
	if n.Network == "xhttp" {
		xhttp := map[string]any{"path": n.Path}
		if n.Host != "" {
			xhttp["host"] = n.Host
		}
		if n.Mode != "" {
			xhttp["mode"] = n.Mode
		}
		extra := make(map[string]json.RawMessage)
		if len(n.Extra) > 0 {
			if err := json.Unmarshal(n.Extra, &extra); err != nil || extra == nil {
				return nil, errors.New("XHTTP extra must be a JSON object")
			}
		}
		// Xray replaces the outer XHTTP settings with extra when it is present,
		// so the connection policy must live inside extra as well. Do not reuse
		// an HTTP client across proxied connections: a stale shared client can
		// otherwise affect later connections until the process is restarted.
		// These limits retire clients from reuse; they do not cut off streams.
		extra["xmux"] = json.RawMessage(`{
			"maxConcurrency": 1,
			"maxConnections": 0,
			"cMaxReuseTimes": 1,
			"hMaxRequestTimes": "600-900",
			"hMaxReusableSecs": "60-120",
			"hKeepAlivePeriod": 15
		}`)
		xhttp["extra"] = extra
		stream["xhttpSettings"] = xhttp
	}
	if n.Security == "reality" {
		if n.Fingerprint == "" {
			n.Fingerprint = "chrome"
		}
		stream["realitySettings"] = map[string]any{"serverName": n.SNI, "fingerprint": n.Fingerprint, "password": n.PublicKey, "shortId": n.ShortID, "spiderX": n.SpiderX}
	} else {
		tls := map[string]any{"serverName": n.SNI}
		if n.Fingerprint != "" {
			tls["fingerprint"] = n.Fingerprint
		}
		if n.ALPN != "" {
			tls["alpn"] = strings.Split(n.ALPN, ",")
		}
		stream["tlsSettings"] = tls
	}
	settings := map[string]any{"address": n.Address, "port": n.Port, "id": n.ID, "encryption": n.Encryption}
	if n.Flow != "" {
		settings["flow"] = n.Flow
	}
	rules := []any{}
	if len(exceptions) > 0 {
		rules = append(rules, map[string]any{"type": "field", "domain": exceptions, "outboundTag": "direct"})
	}
	inbounds := []any{map[string]any{"tag": "socks-in", "listen": "127.0.0.1", "port": socksPort, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"}}}
	if port != 0 {
		inbounds = append(inbounds, map[string]any{"tag": "http-in", "listen": "127.0.0.1", "port": port, "protocol": "http", "settings": map[string]any{"allowTransparent": false}})
	}
	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  inbounds,
		"outbounds": []any{map[string]any{"tag": "proxy", "protocol": "vless", "settings": settings, "streamSettings": stream}, map[string]any{"tag": "direct", "protocol": "freedom"}},
		"routing":   map[string]any{"domainStrategy": "AsIs", "rules": rules},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	config, err := serial.LoadJSONConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("Xray configuration: %w", err)
	}
	instance, err := core.New(config)
	if err != nil {
		return nil, fmt.Errorf("Xray initialization: %w", err)
	}
	if err := instance.Start(); err != nil {
		instance.Close()
		return nil, fmt.Errorf("Xray startup: %w", err)
	}
	return instance, nil
}
