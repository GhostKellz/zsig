//! Key generation and management for Ed25519 cryptographic operations
//! Supports deterministic key derivation, secure memory handling, and multiple output formats
//! Uses pluggable crypto backends for enhanced flexibility

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const fmt = std.fmt;
const base64 = std.base64;
const backend = @import("backend.zig");

/// Ed25519 public key size in bytes
pub const PUBLIC_KEY_SIZE = 32;

/// Ed25519 private key size in bytes (includes public key)
pub const PRIVATE_KEY_SIZE = 64;

/// Ed25519 seed size for key generation
pub const SEED_SIZE = 32;

/// Keypair structure containing both public and private keys
pub const Keypair = struct {
    /// Backend keypair implementation
    inner: backend.Keypair,

    const Self = @This();

/// Generate a new random keypair using the system's CSPRNG
    pub fn generate(allocator: std.mem.Allocator) !Self {
        const inner = try backend.generateKeypair(allocator, .ed25519);
        return Self{ .inner = inner };
    }

    /// Generate a keypair with specific algorithm
    pub fn generateWithAlgorithm(allocator: std.mem.Allocator, algo: backend.Algorithm) !Self {
        const inner = try backend.generateKeypair(allocator, algo);
        return Self{ .inner = inner };
    }

    /// Generate a keypair from a 32-byte seed (deterministic)
    pub fn fromSeed(seed: [SEED_SIZE]u8) Self {
        const inner = backend.keypairFromSeed(seed, .ed25519);
        return Self{ .inner = inner };
    }

    /// Generate a keypair from seed with specific algorithm
    pub fn fromSeedWithAlgorithm(seed: [SEED_SIZE]u8, algo: backend.Algorithm) Self {
        const inner = backend.keypairFromSeed(seed, algo);
        return Self{ .inner = inner };
    }

    /// Generate a keypair from a passphrase using PBKDF2 (brain wallet style)
    pub fn fromPassphrase(allocator: std.mem.Allocator, passphrase: []const u8, salt: ?[]const u8) !Self {
        _ = allocator;
        const actual_salt = salt orelse "zsig-default-salt";

        var seed: [SEED_SIZE]u8 = undefined;
        try crypto.pwhash.pbkdf2(&seed, passphrase, actual_salt, 100000, crypto.auth.hmac.sha2.HmacSha256);

        return fromSeed(seed);
    }

    /// Generate a keypair from passphrase with specific algorithm
    pub fn fromPassphraseWithAlgorithm(allocator: std.mem.Allocator, passphrase: []const u8, salt: ?[]const u8, algo: backend.Algorithm) !Self {
        _ = allocator;
        const actual_salt = salt orelse "zsig-default-salt";

        var seed: [SEED_SIZE]u8 = undefined;
        try crypto.pwhash.pbkdf2(&seed, passphrase, actual_salt, 100000, crypto.auth.hmac.sha2.HmacSha256);

        return fromSeedWithAlgorithm(seed, algo);
    }

    /// Get the algorithm used by this keypair
    pub fn algorithm(self: Self) backend.Algorithm {
        return self.inner.algorithm;
    }

    /// Get public key bytes
    pub fn publicKey(self: *const Self) [PUBLIC_KEY_SIZE]u8 {
        return self.inner.public_key;
    }

    /// Get secret key bytes
    pub fn secretKey(self: *const Self) [32]u8 {
        return self.inner.secret_key;
    }

    /// Export public key as hex string
    pub fn publicKeyHex(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        return try fmt.allocPrint(allocator, "{s}", .{fmt.bytesToHex(&self.inner.public_key, .lower)});
    }

    /// Export private key as base64 (includes both private and public key)
    pub fn privateKeyBase64(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        const encoder = base64.standard.Encoder;
        const encoded_len = encoder.calcSize(32);
        const result = try allocator.alloc(u8, encoded_len);
        _ = encoder.encode(result, &self.inner.secret_key);
        return result;
    }

    /// Export keypair as a bundle (for .key files)
    pub fn exportBundle(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        const private_b64 = try self.privateKeyBase64(allocator);
        defer allocator.free(private_b64);

        const public_hex = try self.publicKeyHex(allocator);
        defer allocator.free(public_hex);

        return try fmt.allocPrint(allocator, "-----BEGIN ZSIG KEYPAIR-----\n" ++
            "Private: {s}\n" ++
            "Public: {s}\n" ++
            "-----END ZSIG KEYPAIR-----\n", .{ private_b64, public_hex });
    }

    /// Import keypair from base64 private key
    pub fn fromPrivateKeyBase64(private_key_b64: []const u8) !Self {
        const decoder = base64.standard.Decoder;
        var secret_key: [32]u8 = undefined;

        try decoder.decode(&secret_key, private_key_b64);

        // Reconstruct the keypair properly from the secret key
        return fromSeed(secret_key);
    }

    /// Import public key from hex string
    pub fn publicKeyFromHex(hex_string: []const u8) ![PUBLIC_KEY_SIZE]u8 {
        var public_key: [PUBLIC_KEY_SIZE]u8 = undefined;
        _ = try fmt.hexToBytes(&public_key, hex_string);
        return public_key;
    }

    /// Export private key in PEM format (PKCS#8)
    pub fn exportPEM(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        // Create ASN.1 DER structure for Ed25519 private key
        // This is a simplified implementation - production would use proper ASN.1 encoding
        
        // Ed25519 private key OID: 1.3.101.112
        const ed25519_oid = [_]u8{0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20};
        
        // Build DER structure: SEQUENCE { version, algorithm, privateKey }
        var der_data = std.ArrayList(u8).init(allocator);
        defer der_data.deinit();
        
        try der_data.appendSlice(&ed25519_oid);
        try der_data.appendSlice(&self.inner.secret_key);
        
        // Base64 encode the DER data
        const encoder = base64.standard.Encoder;
        const encoded_len = encoder.calcSize(der_data.items.len);
        const encoded_data = try allocator.alloc(u8, encoded_len);
        defer allocator.free(encoded_data);
        _ = encoder.encode(encoded_data, der_data.items);
        
        // Format as PEM
        return try fmt.allocPrint(allocator,
            "-----BEGIN PRIVATE KEY-----\n" ++
            "{s}\n" ++
            "-----END PRIVATE KEY-----\n", .{encoded_data});
    }
    
    /// Export public key in PEM format (X.509 SubjectPublicKeyInfo)
    pub fn exportPublicKeyPEM(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        // Create ASN.1 DER structure for Ed25519 public key
        // SubjectPublicKeyInfo for Ed25519
        const ed25519_spki_header = [_]u8{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
        
        var der_data = std.ArrayList(u8).init(allocator);
        defer der_data.deinit();
        
        try der_data.appendSlice(&ed25519_spki_header);
        try der_data.appendSlice(&self.inner.public_key);
        
        // Base64 encode
        const encoder = base64.standard.Encoder;
        const encoded_len = encoder.calcSize(der_data.items.len);
        const encoded_data = try allocator.alloc(u8, encoded_len);
        defer allocator.free(encoded_data);
        _ = encoder.encode(encoded_data, der_data.items);
        
        return try fmt.allocPrint(allocator,
            "-----BEGIN PUBLIC KEY-----\n" ++
            "{s}\n" ++
            "-----END PUBLIC KEY-----\n", .{encoded_data});
    }
    
    /// Import private key from PEM format
    pub fn importPEM(allocator: std.mem.Allocator, pem_data: []const u8) !Self {
        // Extract base64 data between PEM headers
        const begin_marker = "-----BEGIN PRIVATE KEY-----";
        const end_marker = "-----END PRIVATE KEY-----";
        
        const start_pos = mem.indexOf(u8, pem_data, begin_marker) orelse return error.InvalidPEMFormat;
        const end_pos = mem.indexOf(u8, pem_data, end_marker) orelse return error.InvalidPEMFormat;
        
        const b64_start = start_pos + begin_marker.len;
        const b64_data = mem.trim(u8, pem_data[b64_start..end_pos], " \n\r\t");
        
        // Decode base64
        const decoder = base64.standard.Decoder;
        const der_data = try allocator.alloc(u8, try decoder.calcSizeForSlice(b64_data));
        defer allocator.free(der_data);
        
        try decoder.decode(der_data, b64_data);
        
        // Extract private key from DER structure (simplified)
        // In production, would use proper ASN.1 parser
        if (der_data.len < 48) return error.InvalidDERStructure;
        
        // Extract the 32-byte private key (last 32 bytes of the structure)
        const private_key_offset = der_data.len - 32;
        const private_key: [32]u8 = der_data[private_key_offset..][0..32].*;
        
        return fromSeed(private_key);
    }

    /// Securely zero out private key material
    pub fn zeroize(self: *Self) void {
        crypto.utils.secureZero(u8, &self.inner.secret_key);
    }

    /// Sign a message using this keypair
    pub fn sign(self: *const Self, message: []const u8) ![64]u8 {
        return self.inner.sign(message);
    }

    /// Sign a message with additional context
    pub fn signWithContext(self: *const Self, message: []const u8, context: []const u8) ![64]u8 {
        return self.inner.signWithContext(message, context);
    }
};

/// Key derivation utilities for HD wallet support
pub const KeyDerivation = struct {
    /// Derive child key from parent using a simple path (non-BIP32 for now)
    pub fn deriveChild(parent: Keypair, index: u32) Keypair {
        var hasher = crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(&parent.inner.private_key);
        hasher.update(mem.asBytes(&index));

        var child_seed: [SEED_SIZE]u8 = undefined;
        hasher.final(&child_seed);

        return Keypair.fromSeed(child_seed);
    }
};

test "keypair generation" {
    const allocator = std.testing.allocator;

    // Test random generation
    const kp1 = try Keypair.generate(allocator);
    const kp2 = try Keypair.generate(allocator);

    // Keys should be different
    try std.testing.expect(!mem.eql(u8, &kp1.publicKey(), &kp2.publicKey()));
    try std.testing.expect(!mem.eql(u8, &kp1.secretKey(), &kp2.secretKey()));
}

test "deterministic generation from seed" {
    const seed = [_]u8{1} ** 32;

    const kp1 = Keypair.fromSeed(seed);
    const kp2 = Keypair.fromSeed(seed);

    // Should be identical
    try std.testing.expectEqualSlices(u8, &kp1.publicKey(), &kp2.publicKey());
    try std.testing.expectEqualSlices(u8, &kp1.secretKey(), &kp2.secretKey());
}

test "passphrase generation" {
    const allocator = std.testing.allocator;

    const kp1 = try Keypair.fromPassphrase(allocator, "test passphrase", "salt123");
    const kp2 = try Keypair.fromPassphrase(allocator, "test passphrase", "salt123");

    // Should be deterministic
    try std.testing.expectEqualSlices(u8, &kp1.publicKey(), &kp2.publicKey());
    try std.testing.expectEqualSlices(u8, &kp1.secretKey(), &kp2.secretKey());
}

test "export and import" {
    const allocator = std.testing.allocator;

    const original = try Keypair.generate(allocator);

    // Test base64 export/import
    const private_b64 = try original.privateKeyBase64(allocator);
    defer allocator.free(private_b64);

    const imported = try Keypair.fromPrivateKeyBase64(private_b64);

    try std.testing.expectEqualSlices(u8, &original.publicKey(), &imported.publicKey());
    try std.testing.expectEqualSlices(u8, &original.secretKey(), &imported.secretKey());

    // Test hex public key
    const public_hex = try original.publicKeyHex(allocator);
    defer allocator.free(public_hex);

    const public_from_hex = try Keypair.publicKeyFromHex(public_hex);
    try std.testing.expectEqualSlices(u8, &original.publicKey(), &public_from_hex);
}
