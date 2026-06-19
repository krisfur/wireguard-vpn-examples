# WireGuard examples

Two takes on WireGuard for teaching:

- **`0-Go/`** - how you'd write a client in real life: parse a `.conf`, hand it
  to [`wireguard-go`](https://git.zx2c4.com/wireguard-go/), bring the interface
  up. All the crypto is inside the library.
- **`1-Zig/`** - the same protocol from the bottom up: builds a handshake
  initiation message by hand so you can see Curve25519, ChaCha20-Poly1305,
  BLAKE2s, and the Noise_IK key schedule.

## How the VPN works

What the Go client actually does, end to end:

1. **Read the config** - your private key, the server's public key, its
   `Endpoint` (real `host:port`), and which IP ranges go through the tunnel.
2. **Create a TUN device** - a virtual network interface. The OS routes packets
   into it as if it were a real NIC, but they're handed to our program instead.
3. **Handshake with the server** - a Curve25519 key exchange (the Noise_IK
   pattern) that authenticates both sides and derives fresh session keys. This
   is the message the Zig example builds by hand.
4. **Add address + routes** - tell the OS which traffic to send into the TUN
   device (the `AllowedIPs` from the config).
5. **Tunnel traffic** - for each outgoing packet: encrypt it with
   ChaCha20-Poly1305 using the session keys, wrap it in UDP, and send it to the
   server's endpoint. Incoming UDP is decrypted and written back to the TUN
   device. Session keys rotate every couple of minutes.

In the Go example steps 3 and 5 happen inside `wireguard-go`; we only do 1, 2,
and 4.

## Get a config

Grab a `.conf` from your VPN provider (most let you download WireGuard configs,
or generate one with `wg genkey` / `wg-quick`). It looks like:

```ini
[Interface]
PrivateKey = <your private key, base64>
Address = 10.0.0.2/32

[Peer]
PublicKey = <server public key, base64>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

## Run the Go client

```sh
cd 0-Go
go build                       # go.mod is already set up
sudo ./wgclient client.conf    # root: creates a TUN device and routes
```

Run as root/admin: creating a TUN device and editing the routing table is
privileged on every OS.

You can vrify it worked by checking your external IP like:

```bash
curl -s https://api.ipify.org
```

### How it handles the three platforms

The crypto and handshake are identical everywhere - they live in
`wireguard-go`, which is cross-platform. Only the two OS-touching parts differ,
and the code switches on `runtime.GOOS` for each:

- **The TUN device** (`tun.CreateTUN`). Same call, different kernels:
  - *Linux* gives you a named device like `wg0` via `/dev/net/tun`.
  - *macOS* only allows `utun<N>` names, so we request `"utun"` and the kernel
    picks the number - we read it back with `tunDev.Name()`.
  - *Windows* has no TUN by default; `wireguard-go` uses the
    [Wintun](https://www.wintun.net/) driver, which must be installed
    (`wintun.dll` shipped alongside the binary).

- **Address + routing** (`configureInterface`). Each OS has its own tools:
  - *Linux*: `ip address add` / `ip route add`.
  - *macOS*: `ifconfig` and `route add` (BSD tools).
  - *Windows*: `netsh interface ...`.

Shelling out to these commands keeps the example short, but it's not how a real
client works - production tools talk to the kernel directly (netlink on Linux,
route sockets on macOS, the IP Helper API on Windows). The official
`wireguard-go` leaves this out of scope on purpose; `wg-quick` and the
WireGuard apps are what handle it in practice. The default route (`0.0.0.0/0`)
also needs extra handling we skip here for clarity.

## Run the Zig handshake demo

```sh
cd 1-Zig
zig run main.zig    # needs Zig 0.16
```

Prints the 148-byte initiation message. It uses random demo keys, so it won't
authenticate against a real server - it's there to show the bytes, not connect.

## Glossary

| Term | Meaning |
| --- | --- |
| **VPN** | Virtual Private Network - an encrypted tunnel carrying your traffic. |
| **TUN** | A virtual network interface the OS treats like a real one; packets sent to it are handed to a userspace program instead of a wire. |
| **MTU** | Maximum Transmission Unit - the largest packet size an interface will send. |
| **CIDR** | Address-range notation like `10.0.0.0/24`; the `/N` is how many leading bits are the network part. |
| **AllowedIPs** | The CIDRs a peer is allowed to send/receive - doubles as the routing rule for the tunnel. |
| **Endpoint** | The real `host:port` where a peer's UDP packets are sent. |
| **Noise / Noise_IK** | The Noise Protocol Framework; `IK` is the specific handshake pattern where the **I**nitiator already knows the responder's static (**K**) key. |
| **Handshake** | The initial key-agreement exchange that sets up the session keys before data flows. |
| **DH** | Diffie-Hellman - two parties derive a shared secret over a public channel. |
| **Curve25519 / X25519** | The specific elliptic curve (and its DH function) WireGuard uses for key agreement. |
| **Static / ephemeral key** | Static keys are long-lived identity keys; ephemeral keys are fresh per handshake (for forward secrecy). |
| **PSK** | Pre-Shared Key - an optional extra symmetric key mixed in for post-quantum hardening. |
| **AEAD** | Authenticated Encryption with Associated Data - encrypts and authenticates in one step. |
| **ChaCha20-Poly1305** | The AEAD cipher WireGuard uses (ChaCha20 encrypts, Poly1305 authenticates). |
| **BLAKE2s** | The hash function WireGuard uses, including in keyed (MAC) mode. |
| **HASH** | An unkeyed BLAKE2s digest, used to build the running transcript hash. |
| **MAC / mac1 / mac2** | Message Authentication Code; `mac1` proves the sender knows the recipient's public key, `mac2` answers a cookie challenge under load. |
| **HMAC** | Hash-based MAC - the keyed primitive HKDF is built from. |
| **KDF / HKDF** | (HMAC-based) Key Derivation Function - stretches one secret into several keys. |
| **PRF** | Pseudo-Random Function - the building block (here HMAC) that makes a KDF's output look random. |
| **Chaining key** | The evolving secret threaded through each handshake step to bind them together. |
| **TAI64N** | A 12-byte timestamp format WireGuard sends (encrypted) for replay protection. |
| **Nonce** | A number used once per key, so identical plaintexts don't produce identical ciphertexts. |
| **UAPI** | WireGuard's text-based control protocol for configuring a running device. |
| **netlink** | The Linux kernel API for configuring network interfaces and routes. |
| **Wintun** | The Windows TUN driver that `wireguard-go` uses since Windows has no built-in TUN. |
