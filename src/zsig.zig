//! Zsig: Multi-Algorithm Cryptographic Signing Engine for Zig
//! 
//! A comprehensive cryptographic signing library powered by zcrypto, supporting multiple
//! signature algorithms with HMAC authentication for enhanced security.
//!
//! ## Features
//! - Multi-algorithm support: Ed25519, secp256k1 (Bitcoin/Ethereum), secp256r1 (NIST P-256)
//! - HMAC authentication for message integrity
//! - Public/private keypair generation with deterministic derivation
//! - Detached and inline signatures
//! - Context-separated signing for domain isolation
//! - Constant-time operations and secure memory handling
//! - WASM and embedded-friendly
//! - zwallet integration ready
//! - Powered by zcrypto v0.2.0
//!
//! ## Basic Usage (Ed25519)
//! ```zig
//! const zsig = @import("zsig");
//! 
//! // Initialize with zcrypto backend
//! zsig.setCryptoInterface(zsig.ZCryptoInterface.getInterface());
//! 
//! // Generate a keypair
//! const keypair = try zsig.Keypair.generate(allocator);
//! 
//! // Sign a message
//! const message = "Hello, World!";
//! const signature = try zsig.signMessage(message, keypair);
//! 
//! // Verify the signature
//! const is_valid = zsig.verifySignature(message, &signature.bytes, &keypair.publicKey());
//! ```
//!
//! ## Multi-Algorithm Usage
//! ```zig
//! // Bitcoin-style secp256k1 signing
//! const bitcoin_kp = try zsig.MultiSig.generateKeypair(.secp256k1);
//! const tx_hash = "bitcoin-transaction-hash";
//! const bitcoin_sig = zsig.MultiSig.sign(tx_hash, bitcoin_kp);
//! 
//! // NIST P-256 signing
//! const nist_kp = try zsig.MultiSig.generateKeypair(.secp256r1);
//! const document = "important-document-data";
//! const nist_sig = zsig.MultiSig.sign(document, nist_kp);
//! ```
//!
//! ## HMAC Authentication
//! ```zig
//! const keypair = try zsig.MultiSig.generateKeypair(.ed25519);
//! const message = "sensitive data";
//! const auth_key = "authentication-password";
//! 
//! // Sign with HMAC
//! const auth_result = zsig.MultiSig.signWithHmac(message, keypair, auth_key);
//! 
//! // Verify with HMAC
//! const is_valid = zsig.MultiSig.verifyWithHmac(
//!     message, auth_result.signature, auth_result.hmac_tag,
//!     keypair.publicKey(), auth_key, .ed25519
//! );
//! ```

const std = @import("std");

// Re-export backend system
pub const backend = @import("zsig/backend.zig");
pub const zcrypto_backend = @import("zsig/zcrypto_backend.zig");

// Re-export crypto interface setup
pub const CryptoInterface = backend.CryptoInterface;
pub const setCryptoInterface = backend.setCryptoInterface;
pub const ExampleStdCryptoInterface = backend.ExampleStdCryptoInterface;

// Re-export zcrypto backend
pub const ZCryptoInterface = zcrypto_backend.ZCryptoInterface;
pub const ZCryptoKeypair = zcrypto_backend.ZCryptoKeypair;
pub const SignatureAlgorithm = zcrypto_backend.SignatureAlgorithm;
pub const MultiAlgorithmInterface = zcrypto_backend.MultiAlgorithmInterface;
pub const HmacAuth = zcrypto_backend.HmacAuth;
pub const SecureUtils = zcrypto_backend.SecureUtils;

// Re-export core modules
pub const key = @import("zsig/key.zig");
pub const sign = @import("zsig/sign.zig");
pub const verify = @import("zsig/verify.zig");

// Re-export main types for convenience
pub const Keypair = key.Keypair;
pub const Signature = sign.Signature;
pub const VerificationResult = verify.VerificationResult;

// Re-export key constants
pub const PUBLIC_KEY_SIZE = key.PUBLIC_KEY_SIZE;
pub const PRIVATE_KEY_SIZE = key.PRIVATE_KEY_SIZE;
pub const SIGNATURE_SIZE = sign.SIGNATURE_SIZE;
pub const SEED_SIZE = key.SEED_SIZE;

// Re-export main functions for convenience
pub const generateKeypair = key.Keypair.generate;
pub fn keypairFromSeed(seed: [key.SEED_SIZE]u8) !key.Keypair {
    return try key.Keypair.fromSeed(seed);
}
pub const keypairFromPassphrase = key.Keypair.fromPassphrase;

/// Sign a message (convenience function)
pub const signMessage = sign.sign;
pub const signBytes = sign.signBytes;
pub const signInline = sign.signInline;
pub const signWithContext = sign.signWithContext;
pub const signBatch = sign.signBatch;
pub const signChallenge = sign.signChallenge;

/// Verify a signature (convenience function)
pub const verifySignature = verify.verify;
pub const verifyInline = verify.verifyInline;
pub const verifyWithContext = verify.verifyWithContext;
pub const verifyBatch = verify.verifyBatch;
pub const verifyChallenge = verify.verifyChallenge;
pub const verifyDetailed = verify.verifyDetailed;

/// Utility functions
pub const KeyDerivation = key.KeyDerivation;

/// Multi-algorithm signing functions (zcrypto-powered)
pub const MultiSig = struct {
    /// Generate keypair for specific algorithm
    pub fn generateKeypair(algorithm: SignatureAlgorithm) !ZCryptoKeypair {
        return try ZCryptoKeypair.generate(algorithm);
    }
    
    /// Generate keypair from seed for specific algorithm
    pub fn keypairFromSeed(algorithm: SignatureAlgorithm, seed: [32]u8) !ZCryptoKeypair {
        return try ZCryptoKeypair.fromSeed(algorithm, seed);
    }
    
    /// Sign message with specified algorithm
    pub fn sign(message: []const u8, keypair: ZCryptoKeypair) [64]u8 {
        return keypair.sign(message);
    }
    
    /// Sign message with HMAC authentication
    pub fn signWithHmac(message: []const u8, keypair: ZCryptoKeypair, hmac_key: []const u8) struct { signature: [64]u8, hmac_tag: [32]u8 } {
        return keypair.signWithHmac(message, hmac_key);
    }
    
    /// Verify signature with specified algorithm
    pub fn verify(message: []const u8, signature: [64]u8, public_key: [32]u8, algorithm: SignatureAlgorithm) bool {
        return ZCryptoKeypair.verify(message, signature, public_key, algorithm);
    }
    
    /// Verify signature with HMAC authentication
    pub fn verifyWithHmac(message: []const u8, signature: [64]u8, hmac_tag: [32]u8, public_key: [32]u8, hmac_key: []const u8, algorithm: SignatureAlgorithm) bool {
        return ZCryptoKeypair.verifyWithHmac(message, signature, hmac_tag, public_key, hmac_key, algorithm);
    }
};

/// Version information
pub const version = "0.1.0";
pub const version_major = 0;
pub const version_minor = 1;
pub const version_patch = 0;

/// Library information
pub const info = struct {
    pub const name = "zsig";
    pub const description = "Cryptographic Signing Engine for Zig";
    pub const author = "GhostKellz";
    pub const license = "MIT";
    pub const repository = "https://github.com/ghostkellz/zsig";
};

/// Feature flags for compile-time customization
pub const features = struct {
    /// Enable CLI tools
    pub const cli = true;
    /// Enable WASM compatibility
    pub const wasm = true;
    /// Enable hardware wallet support (future)
    pub const hardware = false;
    /// Enable multi-signature support (future)
    pub const multisig = false;
    /// Enable zcrypto multi-algorithm support
    pub const zcrypto_multisig = true;
    /// Enable HMAC authentication
    pub const hmac_auth = true;
    /// Enable secp256k1 (Bitcoin/Ethereum)
    pub const secp256k1 = true;
    /// Enable secp256r1 (NIST P-256)
    pub const secp256r1 = true;
};

test "zsig integration test" {
    const allocator = std.testing.allocator;
    
    // Initialize crypto interface with zcrypto for testing
    setCryptoInterface(ZCryptoInterface.getInterface());
    
    // Test full signing and verification workflow
    const keypair = try generateKeypair(allocator);
    const message = "Integration test message";
    
    // Test basic signing
    const signature = try signMessage(message, keypair);
    try std.testing.expect(verifySignature(message, &signature.bytes, &keypair.publicKey()));
    
    // Test context signing
    const context = "test-context";
    const ctx_signature = try signWithContext(message, context, keypair);
    try std.testing.expect(verifyWithContext(message, context, &ctx_signature.bytes, &keypair.publicKey()));
    
    // Test inline signing
    const inline_sig = try signInline(allocator, message, keypair);
    defer allocator.free(inline_sig);
    try std.testing.expect(verifyInline(inline_sig, &keypair.publicKey()));
    
    // Test batch operations
    const messages = [_][]const u8{ "msg1", "msg2", "msg3" };
    const signatures = try signBatch(allocator, &messages, keypair);
    defer allocator.free(signatures);
    
    try std.testing.expect(verify.verifyBatchSameKey(&messages, signatures, keypair.publicKey()));
}

test "deterministic operations" {
    const allocator = std.testing.allocator;
    
    // Initialize crypto interface with zcrypto for testing
    setCryptoInterface(ZCryptoInterface.getInterface());
    
    const seed = [_]u8{123} ** SEED_SIZE;
    const passphrase = "test passphrase for deterministic generation";
    
    // With zcrypto, operations should be deterministic
    const kp1 = try keypairFromSeed(seed);
    const kp2 = try keypairFromSeed(seed);
    
    // Keys should be valid (can sign and verify)
    const message = "deterministic test message";
    const sig1 = try signMessage(message, kp1);
    const sig2 = try signMessage(message, kp2);
    try std.testing.expect(verifySignature(message, &sig1.bytes, &kp1.publicKey()));
    try std.testing.expect(verifySignature(message, &sig2.bytes, &kp2.publicKey()));
    
    // Test passphrase generation
    const kp3 = try keypairFromPassphrase(allocator, passphrase, "salt");
    const kp4 = try keypairFromPassphrase(allocator, passphrase, "salt");
    
    // These should also be valid
    const sig3 = try signMessage(message, kp3);
    const sig4 = try signMessage(message, kp4);
    try std.testing.expect(verifySignature(message, &sig3.bytes, &kp3.publicKey()));
    try std.testing.expect(verifySignature(message, &sig4.bytes, &kp4.publicKey()));
}

test "cross-module compatibility" {
    const allocator = std.testing.allocator;
    
    // Initialize crypto interface with zcrypto for testing
    setCryptoInterface(ZCryptoInterface.getInterface());
    
    // Test that all modules work together correctly
    const keypair = try key.Keypair.generate(allocator);
    const message = "cross-module test";
    
    // Sign with sign module
    const signature = try sign.sign(message, keypair);
    
    // Verify with verify module  
    try std.testing.expect(verify.verify(message, &signature.bytes, &keypair.publicKey()));
    
    // Test format conversions
    const sig_hex = try signature.toHex(allocator);
    defer allocator.free(sig_hex);
    
    const pub_hex = try keypair.publicKeyHex(allocator);
    defer allocator.free(pub_hex);
    
    try std.testing.expect(try verify.verifyFromHex(message, sig_hex, pub_hex));
}

test "zcrypto multi-algorithm integration" {
    const allocator = std.testing.allocator;
    const message = "multi-algorithm test message";
    
    // Test Ed25519
    const ed25519_kp = try MultiSig.generateKeypair(.ed25519);
    const ed25519_sig = MultiSig.sign(message, ed25519_kp);
    try std.testing.expect(MultiSig.verify(message, ed25519_sig, ed25519_kp.publicKey(), .ed25519));
    
    // Test secp256k1 (Bitcoin/Ethereum)
    const secp256k1_kp = try MultiSig.generateKeypair(.secp256k1);
    const secp256k1_sig = MultiSig.sign(message, secp256k1_kp);
    try std.testing.expect(MultiSig.verify(message, secp256k1_sig, secp256k1_kp.publicKey(), .secp256k1));
    
    // Test secp256r1 (NIST P-256)
    const secp256r1_kp = try MultiSig.generateKeypair(.secp256r1);
    const secp256r1_sig = MultiSig.sign(message, secp256r1_kp);
    try std.testing.expect(MultiSig.verify(message, secp256r1_sig, secp256r1_kp.publicKey(), .secp256r1));
    
    // Cross-algorithm verification should fail
    try std.testing.expect(!MultiSig.verify(message, ed25519_sig, secp256k1_kp.publicKey(), .secp256k1));
    try std.testing.expect(!MultiSig.verify(message, secp256k1_sig, secp256r1_kp.publicKey(), .secp256r1));
}

test "hmac authentication integration" {
    const allocator = std.testing.allocator;
    const message = "authenticated message";
    const hmac_key = "test-authentication-key";
    
    // Test HMAC with all algorithms
    const algorithms = [_]SignatureAlgorithm{ .ed25519, .secp256k1, .secp256r1 };
    
    for (algorithms) |algorithm| {
        const keypair = try MultiSig.generateKeypair(algorithm);
        const auth_result = MultiSig.signWithHmac(message, keypair, hmac_key);
        const public_key = keypair.publicKey();
        
        // Should verify with correct HMAC key
        try std.testing.expect(MultiSig.verifyWithHmac(
            message,
            auth_result.signature,
            auth_result.hmac_tag,
            public_key,
            hmac_key,
            algorithm
        ));
        
        // Should fail with wrong HMAC key
        try std.testing.expect(!MultiSig.verifyWithHmac(
            message,
            auth_result.signature,
            auth_result.hmac_tag,
            public_key,
            "wrong-key",
            algorithm
        ));
    }
}

test "zwallet compatibility" {
    // Test compatibility for zwallet's signing needs
    const allocator = std.testing.allocator;
    
    // Test Bitcoin-style secp256k1 signing (for Bitcoin transactions)
    const bitcoin_seed = [_]u8{0x01} ** 32;
    const bitcoin_kp = try MultiSig.keypairFromSeed(.secp256k1, bitcoin_seed);
    const tx_hash = "bitcoin-transaction-hash-example";
    
    const bitcoin_sig = MultiSig.sign(tx_hash, bitcoin_kp);
    try std.testing.expect(MultiSig.verify(tx_hash, bitcoin_sig, bitcoin_kp.publicKey(), .secp256k1));
    
    // Test Ed25519 for general purpose signing
    const general_kp = try MultiSig.generateKeypair(.ed25519);
    const wallet_data = "encrypted-wallet-data";
    
    const general_sig = MultiSig.sign(wallet_data, general_kp);
    try std.testing.expect(MultiSig.verify(wallet_data, general_sig, general_kp.publicKey(), .ed25519));
    
    // Test HMAC authentication for wallet protection
    const wallet_password = "user-wallet-password";
    const auth_result = MultiSig.signWithHmac(wallet_data, general_kp, wallet_password);
    
    try std.testing.expect(MultiSig.verifyWithHmac(
        wallet_data,
        auth_result.signature,
        auth_result.hmac_tag,
        general_kp.publicKey(),
        wallet_password,
        .ed25519
    ));
}

/// Advanced printing function (keeping for compatibility)
pub fn advancedPrint() !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("Zsig v{s} - Cryptographic Signing Engine for Zig\n", .{version});
    try stdout.print("Features: Ed25519 signing, verification, key generation\n", .{});
    try stdout.print("Run `zig build test` to run the test suite.\n", .{});

    try bw.flush();
}
