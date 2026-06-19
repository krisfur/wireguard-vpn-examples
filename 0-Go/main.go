// A minimal WireGuard client built on wireguard-go. The crypto, handshake,
// and data plane all live inside the imported packages; we just parse a
// config, hand it to the device, and bring up the interface.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type Config struct {
	PrivateKey string
	Address    string
	PeerPublic string
	Endpoint   string
	AllowedIPs string
	Keepalive  string
}

func parseConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := &Config{}
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch section {
		case "interface":
			switch k {
			case "PrivateKey":
				cfg.PrivateKey = v
			case "Address":
				cfg.Address = v
			}
		case "peer":
			switch k {
			case "PublicKey":
				cfg.PeerPublic = v
			case "Endpoint":
				cfg.Endpoint = v
			case "AllowedIPs":
				cfg.AllowedIPs = v
			case "PersistentKeepalive":
				cfg.Keepalive = v
			}
		}
	}
	return cfg, sc.Err()
}

// .conf files store keys in base64; the UAPI protocol wants hex.
func keyToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("expected 32-byte key, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func uapiConfig(cfg *Config) (string, error) {
	privHex, err := keyToHex(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	pubHex, err := keyToHex(cfg.PeerPublic)
	if err != nil {
		return "", fmt.Errorf("peer key: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	fmt.Fprintf(&b, "public_key=%s\n", pubHex)
	if cfg.Endpoint != "" {
		fmt.Fprintf(&b, "endpoint=%s\n", cfg.Endpoint)
	}
	for ip := range strings.SplitSeq(cfg.AllowedIPs, ",") {
		if ip = strings.TrimSpace(ip); ip != "" {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
		}
	}
	if cfg.Keepalive != "" {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%s\n", cfg.Keepalive)
	}
	return b.String(), nil
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <config.conf>", os.Args[0])
	}
	cfg, err := parseConfig(os.Args[1])
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// macOS only allows utun<N> names and assigns the number itself; Linux and
	// Windows take the name we ask for.
	reqName := "wg0"
	if runtime.GOOS == "darwin" {
		reqName = "utun"
	}
	tunDev, err := tun.CreateTUN(reqName, device.DefaultMTU)
	if err != nil {
		log.Fatalf("create tun: %v", err)
	}
	iface, err := tunDev.Name()
	if err != nil {
		log.Fatalf("tun name: %v", err)
	}

	// This device object contains everything the Zig example builds by hand:
	// the Noise_IK handshake, Curve25519, ChaCha20-Poly1305, BLAKE2s, key
	// rotation, keepalives, cookies, and the encrypt/decrypt data plane.
	logger := device.NewLogger(device.LogLevelVerbose, fmt.Sprintf("(%s) ", iface))
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	uapi, err := uapiConfig(cfg)
	if err != nil {
		log.Fatalf("build uapi config: %v", err)
	}
	if err := dev.IpcSet(uapi); err != nil {
		log.Fatalf("ipc set: %v", err)
	}
	if err := dev.Up(); err != nil {
		log.Fatalf("device up: %v", err)
	}

	// wireguard-go never touches the routing table, so we set the address and
	// routes ourselves. The OS networking tools differ per platform (a real
	// tool would use netlink / route sockets / the IP Helper API instead).
	cleanup := configureInterface(iface, cfg)

	// Clean up on Ctrl-C: closing the device drops the interface (and its
	// routes); cleanup() removes the host route we added to the server.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	log.Printf("%s is up. Ctrl-C to stop.", iface)
	select {
	case <-sig:
	case <-dev.Wait():
	}
	cleanup()
	dev.Close()
}

func configureInterface(iface string, cfg *Config) func() {
	addrs := splitList(cfg.Address) // a config may carry both a v4 and v6 address
	haveV6Addr := false
	for _, a := range addrs {
		if strings.Contains(a, ":") {
			haveV6Addr = true
		}
	}

	switch runtime.GOOS {
	case "linux":
		for _, a := range addrs {
			run("ip", "address", "add", a, "dev", iface)
		}
		run("ip", "link", "set", "up", "dev", iface)
		for _, ip := range routes(cfg) {
			run("ip", "route", "add", ip, "dev", iface)
		}
	case "darwin":
		for _, a := range addrs {
			ip, prefix, _ := strings.Cut(a, "/")
			if strings.Contains(ip, ":") {
				run("ifconfig", iface, "inet6", ip, "prefixlen", prefix)
			} else {
				run("ifconfig", iface, "inet", ip, ip) // point-to-point
			}
		}
		run("ifconfig", iface, "up")
		for _, ip := range routes(cfg) {
			family := "-inet"
			if strings.Contains(ip, ":") {
				family = "-inet6"
			}
			run("route", "-q", "-n", "add", family, ip, "-interface", iface)
		}
	case "windows":
		for _, a := range addrs {
			ip, _, _ := strings.Cut(a, "/")
			if strings.Contains(ip, ":") {
				run("netsh", "interface", "ipv6", "add", "address", iface, a)
			} else {
				run("netsh", "interface", "ip", "set", "address",
					"name="+iface, "source=static", "addr="+ip, "mask=255.255.255.255")
			}
		}
		for _, ip := range routes(cfg) {
			proto := "ipv4"
			if strings.Contains(ip, ":") {
				proto = "ipv6"
			}
			run("netsh", "interface", proto, "add", "route", ip, "name="+iface)
		}
	default:
		log.Printf("warn: don't know how to configure routes on %s", runtime.GOOS)
	}

	v4, v6 := hasDefaultRoute(cfg)
	v6 = v6 && haveV6Addr // can't route v6 through an interface with no v6 address
	if v4 || v6 {
		return addDefaultRoute(iface, cfg, v4, v6)
	}
	return func() {}
}

// splitList splits a comma-separated config value and trims each entry.
func splitList(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// addDefaultRoute sends all traffic through the tunnel, the wg-quick way:
// pin a host route to the server via the real gateway (so the encrypted
// packets themselves don't loop into the tunnel), then route the whole
// address space via the interface using two /1 halves, which beat the
// existing 0.0.0.0/0 default by longest-prefix match without replacing it.
// Returns a cleanup that removes the host route (the /1 routes vanish with
// the interface). Linux and macOS only.
func addDefaultRoute(iface string, cfg *Config, v4, v6 bool) func() {
	gw, err := defaultGateway()
	if err != nil {
		log.Printf("warn: full tunnel needs the default gateway: %v", err)
		return func() {}
	}
	server, err := endpointIP(cfg.Endpoint)
	if err != nil {
		log.Printf("warn: full tunnel needs the server IP: %v", err)
		return func() {}
	}

	switch runtime.GOOS {
	case "linux":
		run("ip", "route", "add", server, "via", gw)
		if v4 {
			run("ip", "route", "add", "0.0.0.0/1", "dev", iface)
			run("ip", "route", "add", "128.0.0.0/1", "dev", iface)
		}
		if v6 {
			run("ip", "-6", "route", "add", "::/1", "dev", iface)
			run("ip", "-6", "route", "add", "8000::/1", "dev", iface)
		}
		return func() { run("ip", "route", "del", server) }
	case "darwin":
		run("route", "-q", "-n", "add", "-host", server, gw)
		if v4 {
			run("route", "-q", "-n", "add", "-net", "0.0.0.0/1", "-interface", iface)
			run("route", "-q", "-n", "add", "-net", "128.0.0.0/1", "-interface", iface)
		}
		if v6 {
			run("route", "-q", "-n", "add", "-inet6", "-net", "::/1", "-interface", iface)
			run("route", "-q", "-n", "add", "-inet6", "-net", "8000::/1", "-interface", iface)
		}
		return func() { run("route", "-q", "-n", "delete", "-host", server) }
	default:
		log.Printf("warn: full tunnel not implemented on %s", runtime.GOOS)
		return func() {}
	}
}

// hasDefaultRoute reports whether AllowedIPs asks to tunnel all v4 / v6 traffic.
func hasDefaultRoute(cfg *Config) (v4, v6 bool) {
	for ip := range strings.SplitSeq(cfg.AllowedIPs, ",") {
		switch strings.TrimSpace(ip) {
		case "0.0.0.0/0":
			v4 = true
		case "::/0":
			v6 = true
		}
	}
	return
}

// defaultGateway returns the current IPv4 default gateway from the OS.
func defaultGateway() (string, error) {
	switch runtime.GOOS {
	case "linux":
		out, err := exec.Command("ip", "route", "show", "default").Output()
		if err != nil {
			return "", err
		}
		if f := strings.Fields(string(out)); len(f) >= 3 && f[0] == "default" {
			return f[2], nil // "default via <gw> dev ..."
		}
	case "darwin":
		out, err := exec.Command("route", "-n", "get", "default").Output()
		if err != nil {
			return "", err
		}
		for line := range strings.SplitSeq(string(out), "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && k == "gateway" {
				return strings.TrimSpace(v), nil
			}
		}
	}
	return "", fmt.Errorf("no default gateway found")
}

// endpointIP resolves the Peer Endpoint (host:port) to an IPv4 address.
func endpointIP(endpoint string) (string, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", err
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address for %s", host)
}

// routes returns the AllowedIPs to install as routes, skipping the default
// routes (0.0.0.0/0 and ::/0) which need extra handling we leave out for clarity.
func routes(cfg *Config) []string {
	var out []string
	for _, ip := range splitList(cfg.AllowedIPs) {
		if ip != "0.0.0.0/0" && ip != "::/0" {
			out = append(out, ip)
		}
	}
	return out
}

func run(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("warn: %s %s: %v", name, strings.Join(args, " "), err)
	}
}
