//! Building a WireGuard handshake initiation message (type 1) by hand.
//!
//! The opposite of the Go example: nothing is delegated, so every cryptographic
//! step is visible. This is a teaching artifact, not production crypto - use a
//! reviewed implementation for anything real.
//!
//! Written for Zig 0.16, which routes randomness, time, and stdout through the
//! std.Io interface; older Zig used std.crypto.random / std.time directly.

const std = @import("std");

const Blake2s256 = std.crypto.hash.blake2.Blake2s256;
const Blake2s128 = std.crypto.hash.blake2.Blake2s(128);
const HmacBlake2s = std.crypto.auth.hmac.Hmac(Blake2s256);
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const X25519 = std.crypto.dh.X25519;

const CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1 = "mac1----";
const BASE_POINT = [_]u8{9} ++ [_]u8{0} ** 31;

fn hash(out: *[32]u8, parts: []const []const u8) void {
    var st = Blake2s256.init(.{});
    for (parts) |p| st.update(p);
    st.final(out);
}

fn hmac(out: *[32]u8, key: []const u8, data: []const u8) void {
    HmacBlake2s.create(out, data, key);
}

// HKDF as WireGuard uses it: from a chaining key and input, produce n 32-byte
// outputs (n is 1, 2, or 3 in the protocol).
fn kdf(comptime n: usize, key: []const u8, input: []const u8) [n][32]u8 {
    var prk: [32]u8 = undefined;
    hmac(&prk, key, input);

    var out: [n][32]u8 = undefined;
    var prev: [32]u8 = undefined;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        var buf: [33]u8 = undefined;
        var len: usize = 0;
        if (i > 0) {
            @memcpy(buf[0..32], &prev);
            len = 32;
        }
        buf[len] = @intCast(i + 1);
        len += 1;
        hmac(&prev, &prk, buf[0..len]);
        out[i] = prev;
    }
    return out;
}

fn dh(secret: [32]u8, public: [32]u8) [32]u8 {
    return X25519.scalarmult(secret, public) catch unreachable;
}

// TAI64N timestamp: 8-byte TAI64 seconds + 4-byte nanoseconds, big-endian.
// Used for replay protection.
fn tai64n(io: std.Io, out: *[12]u8) void {
    const ns = std.Io.Timestamp.now(io, .real).nanoseconds;
    const secs: u64 = @intCast(@divTrunc(ns, std.time.ns_per_s));
    const sub_ns: u32 = @intCast(@mod(ns, std.time.ns_per_s));
    std.mem.writeInt(u64, out[0..8], 0x400000000000000a + secs, .big);
    std.mem.writeInt(u32, out[8..12], sub_ns, .big);
}

// Wire layout (148 bytes, little-endian fields):
//   [0]   type = 1 + 3 reserved zero bytes
//   [4]   sender index (4)
//   [8]   ephemeral public key (32)
//   [40]  encrypted static public key (32 + 16 tag)
//   [88]  encrypted TAI64N timestamp (12 + 16 tag)
//   [116] mac1 (16)
//   [132] mac2 (16, left zero - no cookie challenge)
const MSG_LEN = 148;
const OFF_SENDER = 4;
const OFF_EPHEMERAL = 8;
const OFF_STATIC = 40;
const OFF_TIMESTAMP = 88;
const OFF_MAC1 = 116;

fn buildInitiation(
    io: std.Io,
    msg: *[MSG_LEN]u8,
    s_priv: [32]u8,
    s_pub: [32]u8,
    peer_pub: [32]u8,
) void {
    @memset(msg, 0);
    msg[0] = 1;
    io.random(msg[OFF_SENDER..][0..4]);

    // Seed the chaining key c and transcript hash h. Mixing the responder's
    // public key in up front is what makes this the "IK" pattern.
    var c: [32]u8 = undefined;
    hash(&c, &.{CONSTRUCTION});
    var h: [32]u8 = undefined;
    hash(&h, &.{ &c, IDENTIFIER });
    hash(&h, &.{ &h, &peer_pub });

    // Ephemeral key, sent in the clear.
    var e_priv: [32]u8 = undefined;
    io.random(&e_priv);
    const e_pub = dh(e_priv, BASE_POINT);
    @memcpy(msg[OFF_EPHEMERAL..][0..32], &e_pub);
    {
        const r = kdf(1, &c, &e_pub);
        c = r[0];
    }
    hash(&h, &.{ &h, &e_pub });

    // Encrypt our identity. The key is DH(ephemeral, responder_static), so only
    // the holder of the responder private key can decrypt it - identity hiding.
    {
        const shared = dh(e_priv, peer_pub);
        const r = kdf(2, &c, &shared);
        c = r[0];
        const k = r[1];

        const nonce = [_]u8{0} ** 12;
        var tag: [16]u8 = undefined;
        ChaCha20Poly1305.encrypt(msg[OFF_STATIC..][0..32], &tag, &s_pub, &h, nonce, k);
        @memcpy(msg[OFF_STATIC + 32 ..][0..16], &tag);
        hash(&h, &.{ &h, msg[OFF_STATIC..][0..48] });
    }

    // Encrypt the timestamp. The key is DH(our_static, responder_static), a
    // static-static exchange that authenticates us to the responder.
    {
        const shared = dh(s_priv, peer_pub);
        const r = kdf(2, &c, &shared);
        c = r[0];
        const k = r[1];

        var ts: [12]u8 = undefined;
        tai64n(io, &ts);
        const nonce = [_]u8{0} ** 12;
        var tag: [16]u8 = undefined;
        ChaCha20Poly1305.encrypt(msg[OFF_TIMESTAMP..][0..12], &tag, &ts, &h, nonce, k);
        @memcpy(msg[OFF_TIMESTAMP + 12 ..][0..16], &tag);
        hash(&h, &.{ &h, msg[OFF_TIMESTAMP..][0..28] });
    }

    // mac1: keyed BLAKE2s over everything before the mac fields. Lets the
    // responder cheaply discard packets from anyone who doesn't know its key.
    var mac1_key: [32]u8 = undefined;
    hash(&mac1_key, &.{ LABEL_MAC1, &peer_pub });
    Blake2s128.hash(msg[0..OFF_MAC1], msg[OFF_MAC1..][0..16], .{ .key = &mac1_key });
}

pub fn main() !void {
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Demo keys. peer_pub is random here, so the message is structurally valid
    // but won't authenticate against any real responder.
    var s_priv: [32]u8 = undefined;
    io.random(&s_priv);
    const s_pub = dh(s_priv, BASE_POINT);

    var peer_pub: [32]u8 = undefined;
    io.random(&peer_pub);

    var msg: [MSG_LEN]u8 = undefined;
    buildInitiation(io, &msg, s_priv, s_pub, peer_pub);

    var buf: [256]u8 = undefined;
    var fw = std.Io.File.stdout().writer(io, &buf);
    const out = &fw.interface;
    try out.print("handshake initiation, {d} bytes:\n", .{MSG_LEN});
    for (msg, 0..) |b, i| {
        try out.print("{x:0>2}{s}", .{ b, if ((i + 1) % 16 == 0) "\n" else " " });
    }
    try out.print("\n", .{});
    try out.flush();
}
