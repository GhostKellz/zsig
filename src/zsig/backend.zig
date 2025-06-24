//! Crypto backend interface for zsig
//! Supports multiple crypto implementations: std.crypto, zcrypto, etc.

const std = @import("std");
const zcrypto = @import("zcrypto");

/// Compile-time crypto backend selection
pub const Backend = enum {
    std_crypto,
    zcrypto,
    
    // Default to zcrypto since std.crypto Ed25519 API is different
    pub const default: Backend = .zcrypto;
};

/// Ed25519 keypair interface
pub const Keypair = struct {
    public_key: [32]u8,
    secret_key: [64]u8,
    
    const Self = @This();
    
    /// Generate a new random keypair using the selected backend
    pub fn generate(allocator: std.mem.Allocator) !Self {
        return switch (comptime Backend.default) {
            .std_crypto => generateStdCrypto(allocator),
            .zcrypto => generateZCrypto(allocator),
        };
    }
    
    /// Generate keypair from seed
    pub fn fromSeed(seed: [32]u8) !Self {
        return switch (comptime Backend.default) {
            .std_crypto => try fromSeedStdCrypto(seed),
            .zcrypto => try fromSeedZCrypto(seed),
        };
    }
    
    /// Sign a message
    pub fn sign(self: Self, message: []const u8) [64]u8 {
        return switch (comptime Backend.default) {
            .std_crypto => signStdCrypto(self, message),
            .zcrypto => signZCrypto(self, message),
        };
    }
    
    /// Sign with additional context for domain separation
    pub fn signWithContext(self: Self, message: []const u8, context: []const u8) [64]u8 {
        return switch (comptime Backend.default) {
            .std_crypto => signWithContextStdCrypto(self, message, context),
            .zcrypto => signWithContextZCrypto(self, message, context),
        };
    }
};

/// Signature verification interface
pub const Verifier = struct {
    /// Verify a signature
    pub fn verify(message: []const u8, signature: [64]u8, public_key: [32]u8) bool {
        return switch (comptime Backend.default) {
            .std_crypto => verifyStdCrypto(message, signature, public_key),
            .zcrypto => verifyZCrypto(message, signature, public_key),
        };
    }
    
    /// Verify with context
    pub fn verifyWithContext(message: []const u8, context: []const u8, signature: [64]u8, public_key: [32]u8) bool {
        return switch (comptime Backend.default) {
            .std_crypto => verifyWithContextStdCrypto(message, context, signature, public_key),
            .zcrypto => verifyWithContextZCrypto(message, context, signature, public_key),
        };
    }
};

// =============================================================================
// std.crypto backend implementation
// =============================================================================

fn generateStdCrypto(allocator: std.mem.Allocator) !Keypair {
    _ = allocator; // std.crypto doesn't need allocator
    const kp = std.crypto.sign.Ed25519.KeyPair.generate();
    return Keypair{
        .public_key = kp.public_key.bytes,
        .secret_key = kp.secret_key.bytes,
    };
}

fn fromSeedStdCrypto(seed: [32]u8) !Keypair {
    _ = seed;
    // TODO: Implement proper Ed25519 key derivation from seed
    // For now, just generate a random keypair
    return generateStdCrypto(std.heap.page_allocator);
}

fn signStdCrypto(keypair: Keypair, message: []const u8) [64]u8 {
    // Direct signing using Ed25519.sign function
    const signature_struct = std.crypto.sign.Ed25519.sign(message, keypair.secret_key[0..32].*, null) catch unreachable;
    return signature_struct.toBytes();
}

fn signWithContextStdCrypto(keypair: Keypair, message: []const u8, context: []const u8) [64]u8 {
    // For std.crypto, we'll hash context + message for domain separation
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update("zsig-context:");
    hasher.update(context);
    hasher.update(":");
    hasher.update(message);
    
    var hashed_message: [32]u8 = undefined;
    hasher.final(&hashed_message);
    
    const signature = std.crypto.sign.Ed25519.sign(&hashed_message, keypair.secret_key[0..32].*, null) catch unreachable;
    return signature.toBytes();
}

fn verifyStdCrypto(message: []const u8, signature: [64]u8, public_key: [32]u8) bool {
    const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key) catch return false;
    const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature);
    sig.verify(message, pub_key) catch return false;
    return true;
}

fn verifyWithContextStdCrypto(message: []const u8, context: []const u8, signature: [64]u8, public_key: [32]u8) bool {
    // Recreate the same hashed message as in signing
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update("zsig-context:");
    hasher.update(context);
    hasher.update(":");
    hasher.update(message);
    
    var hashed_message: [32]u8 = undefined;
    hasher.final(&hashed_message);
    
    return verifyStdCrypto(&hashed_message, signature, public_key);
}

// =============================================================================
// zcrypto backend implementation
// =============================================================================

fn generateZCrypto(allocator: std.mem.Allocator) !Keypair {
    _ = allocator; // zcrypto doesn't need allocator
    const kp = zcrypto.asym.ed25519.generate();
    return Keypair{
        .public_key = kp.public_key,
        .secret_key = kp.private_key,
    };
}

fn fromSeedZCrypto(seed: [32]u8) !Keypair {
    _ = seed;
    // TODO: Implement proper deterministic key generation from seed
    // For now, just generate a random keypair  
    return generateZCrypto(std.heap.page_allocator);
}

fn signZCrypto(keypair: Keypair, message: []const u8) [64]u8 {
    return zcrypto.asym.ed25519.sign(message, keypair.secret_key);
}

fn signWithContextZCrypto(keypair: Keypair, message: []const u8, context: []const u8) [64]u8 {
    // For zcrypto, we'll use a domain separator approach
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update("zsig-context:");
    hasher.update(context);
    hasher.update(":");
    hasher.update(message);
    
    var hashed_message: [32]u8 = undefined;
    hasher.final(&hashed_message);
    
    return zcrypto.asym.ed25519.sign(&hashed_message, keypair.secret_key);
}

fn verifyZCrypto(message: []const u8, signature: [64]u8, public_key: [32]u8) bool {
    return zcrypto.asym.ed25519.verify(message, signature, public_key);
}

fn verifyWithContextZCrypto(message: []const u8, context: []const u8, signature: [64]u8, public_key: [32]u8) bool {
    // Recreate the same hashed message as in signing
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update("zsig-context:");
    hasher.update(context);
    hasher.update(":");
    hasher.update(message);
    
    var hashed_message: [32]u8 = undefined;
    hasher.final(&hashed_message);
    
    return zcrypto.asym.ed25519.verify(&hashed_message, signature, public_key);
}
