//! Pure Zig cryptographic backend for zsig v0.5.0
//! Provides Ed25519 signing and verification using std.crypto

const std = @import("std");
const crypto = @import("../crypto/ed25519.zig");
const blake3 = @import("../crypto/blake3.zig");

// Re-export for compatibility
pub const ed25519 = crypto;

/// Supported cryptographic algorithms
pub const Algorithm = enum {
    ed25519,
    ml_dsa_65,
    hybrid_x25519_ml_kem,

    pub fn toString(self: Algorithm) []const u8 {
        return switch (self) {
            .ed25519 => "ed25519",
            .ml_dsa_65 => "ml_dsa_65",
            .hybrid_x25519_ml_kem => "hybrid_x25519_ml_kem",
        };
    }
};

/// Parse algorithm from string
pub fn algorithmFromString(algorithm_str: []const u8) !Algorithm {
    if (std.mem.eql(u8, algorithm_str, "ed25519")) {
        return .ed25519;
    } else if (std.mem.eql(u8, algorithm_str, "ml_dsa_65")) {
        return .ml_dsa_65;
    } else if (std.mem.eql(u8, algorithm_str, "hybrid_x25519_ml_kem")) {
        return .hybrid_x25519_ml_kem;
    }
    return error.UnsupportedAlgorithm;
}

/// Keypair structure for the backend
pub const Keypair = struct {
    secret_key: [32]u8,
    public_key: [32]u8,
    algorithm: Algorithm,

    /// Generate a new random keypair
    pub fn generate(algorithm: Algorithm) !Keypair {
        switch (algorithm) {
            .ed25519 => {
                const kp = crypto.KeyPair.generate();
                return Keypair{
                    .secret_key = kp.private_key,
                    .public_key = kp.public_key,
                    .algorithm = algorithm,
                };
            },
            .ml_dsa_65, .hybrid_x25519_ml_kem => {
                return error.UnsupportedAlgorithm;
            },
        }
    }

    /// Create keypair from seed
    pub fn fromSeed(seed: [32]u8, algorithm: Algorithm) !Keypair {
        switch (algorithm) {
            .ed25519 => {
                const kp = crypto.KeyPair.fromSeed(seed);
                return Keypair{
                    .secret_key = kp.private_key,
                    .public_key = kp.public_key,
                    .algorithm = algorithm,
                };
            },
            .ml_dsa_65, .hybrid_x25519_ml_kem => {
                return error.UnsupportedAlgorithm;
            },
        }
    }

    /// Sign a message
    pub fn sign(self: *const Keypair, message: []const u8) ![64]u8 {
        switch (self.algorithm) {
            .ed25519 => {
                const kp = crypto.KeyPair{
                    .private_key = self.secret_key,
                    .public_key = self.public_key,
                };
                return kp.sign(message);
            },
            .ml_dsa_65, .hybrid_x25519_ml_kem => {
                return error.UnsupportedAlgorithm;
            },
        }
    }

    /// Sign a message with additional context
    pub fn signWithContext(self: *const Keypair, message: []const u8, context: []const u8) ![64]u8 {
        // Create domain-separated hash
        const domain_separated = hashWithContext(context, message);
        return self.sign(&domain_separated);
    }

    /// Get public key as hex string
    pub fn publicKeyHex(self: *const Keypair, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&self.public_key)});
    }

    /// Get secret key as hex string
    pub fn secretKeyHex(self: *const Keypair, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&self.secret_key)});
    }
};

/// Signature structure
pub const Signature = struct {
    bytes: [64]u8,
    algorithm: Algorithm,

    /// Create signature from bytes
    pub fn fromBytes(bytes: [64]u8, algorithm: Algorithm) Signature {
        return Signature{
            .bytes = bytes,
            .algorithm = algorithm,
        };
    }

    /// Get signature as hex string
    pub fn toHex(self: *const Signature, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&self.bytes)});
    }

    /// Verify signature against message and public key
    pub fn verify(self: *const Signature, message: []const u8, public_key: [32]u8) bool {
        switch (self.algorithm) {
            .ed25519 => {
                return crypto.verifySignature(message, self.bytes, public_key);
            },
            .ml_dsa_65, .hybrid_x25519_ml_kem => {
                return false; // Unsupported algorithms
            },
        }
    }
};

/// Sign a message with a keypair
pub fn sign(keypair: *const Keypair, message: []const u8) ![64]u8 {
    return keypair.sign(message);
}

/// Verify a signature
pub fn verify(signature: [64]u8, message: []const u8, public_key: [32]u8, algorithm: Algorithm) bool {
    const sig = Signature.fromBytes(signature, algorithm);
    return sig.verify(message, public_key);
}

/// Verify a signature using a keypair (uses keypair's algorithm and public key)
pub fn verifyWithKeypairAlgorithm(message: []const u8, signature: [64]u8, keypair: anytype) bool {
    return verify(signature, message, keypair.inner.public_key, keypair.inner.algorithm);
}

/// Batch verification (for performance)
pub fn verifyBatch(allocator: std.mem.Allocator, items: []const struct {
    signature: [64]u8,
    message: []const u8,
    public_key: [32]u8,
    algorithm: Algorithm,
}) !bool {
    _ = allocator; // Future optimization opportunity

    // For now, verify each individually
    for (items) |item| {
        if (!verify(item.signature, item.message, item.public_key, item.algorithm)) {
            return false;
        }
    }
    return true;
}

/// Hash function used for domain separation
pub fn hash(data: []const u8) [32]u8 {
    return blake3.hash(data);
}

/// Hash with context for domain separation
pub fn hashWithContext(context: []const u8, data: []const u8) [32]u8 {
    return blake3.hashWithContext(context, data);
}

/// Generate a keypair (legacy function name for compatibility)
pub fn generateKeypair(allocator: std.mem.Allocator, algorithm: Algorithm) !Keypair {
    _ = allocator; // Not needed for this implementation
    return Keypair.generate(algorithm);
}

/// Create keypair from seed (legacy function name for compatibility)
pub fn keypairFromSeed(seed: [32]u8, algorithm: Algorithm) Keypair {
    return Keypair.fromSeed(seed, algorithm) catch unreachable;
}
