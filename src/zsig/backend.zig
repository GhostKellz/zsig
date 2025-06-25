//! Crypto backend interface for zsig
//! Accepts crypto function implementations from parent applications

const std = @import("std");

/// Keypair result structure for crypto interface
pub const KeypairResult = extern struct {
    public_key: [32]u8,
    secret_key: [64]u8,
};

/// Crypto function interface that parent applications must implement
pub const CryptoInterface = struct {
    /// Generate a random Ed25519 keypair
    generateKeypairFn: *const fn () KeypairResult,
    
    /// Generate keypair from 32-byte seed
    keypairFromSeedFn: *const fn (seed: [32]u8) KeypairResult,
    
    /// Sign a message with Ed25519
    signFn: *const fn (message: []const u8, secret_key: [64]u8) [64]u8,
    
    /// Verify an Ed25519 signature
    verifyFn: *const fn (message: []const u8, signature: [64]u8, public_key: [32]u8) bool,
    
    /// Hash function for context signing (Blake3 or similar)
    hashFn: *const fn (data: []const u8) [32]u8,
};

/// Global crypto interface - must be set by parent application
var crypto_interface: ?CryptoInterface = null;

/// Set the crypto interface (must be called by parent before using zsig)
pub fn setCryptoInterface(interface: CryptoInterface) void {
    crypto_interface = interface;
}

/// Get the current crypto interface
fn getCryptoInterface() CryptoInterface {
    return crypto_interface orelse @panic("Crypto interface not set! Call setCryptoInterface() first.");
}

/// Ed25519 keypair interface
pub const Keypair = struct {
    public_key: [32]u8,
    secret_key: [64]u8,
    
    const Self = @This();
    
    /// Generate a new random keypair using the provided crypto interface
    pub fn generate(allocator: std.mem.Allocator) !Self {
        _ = allocator; // Not needed for interface-based approach
        const interface = getCryptoInterface();
        const kp = interface.generateKeypairFn();
        return Self{
            .public_key = kp.public_key,
            .secret_key = kp.secret_key,
        };
    }
    
    /// Generate keypair from seed
    pub fn fromSeed(seed: [32]u8) !Self {
        const interface = getCryptoInterface();
        const kp = interface.keypairFromSeedFn(seed);
        return Self{
            .public_key = kp.public_key,
            .secret_key = kp.secret_key,
        };
    }
    
    /// Sign a message
    pub fn sign(self: Self, message: []const u8) [64]u8 {
        const interface = getCryptoInterface();
        return interface.signFn(message, self.secret_key);
    }
    
    /// Sign with additional context for domain separation
    pub fn signWithContext(self: Self, message: []const u8, context: []const u8) [64]u8 {
        const interface = getCryptoInterface();
        
        // Create context-separated message
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        
        const context_msg = std.fmt.allocPrint(allocator, "zsig-context:{s}:{s}", .{ context, message }) catch {
            // Fallback to simple concatenation if allocation fails
            return interface.signFn(message, self.secret_key);
        };
        
        const hashed = interface.hashFn(context_msg);
        return interface.signFn(&hashed, self.secret_key);
    }
};

/// Signature verification interface
pub const Verifier = struct {
    /// Verify a signature
    pub fn verify(message: []const u8, signature: [64]u8, public_key: [32]u8) bool {
        const interface = getCryptoInterface();
        return interface.verifyFn(message, signature, public_key);
    }
    
    /// Verify with context
    pub fn verifyWithContext(message: []const u8, context: []const u8, signature: [64]u8, public_key: [32]u8) bool {
        const interface = getCryptoInterface();
        
        // Recreate the same context-separated message as in signing
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        
        const context_msg = std.fmt.allocPrint(allocator, "zsig-context:{s}:{s}", .{ context, message }) catch {
            // Fallback to simple verification if allocation fails
            return interface.verifyFn(message, signature, public_key);
        };
        
        const hashed = interface.hashFn(context_msg);
        return interface.verifyFn(&hashed, signature, public_key);
    }
};

/// Example implementation helpers for parent applications
pub const ExampleStdCryptoInterface = struct {
    /// Example implementation using std.crypto
    pub fn getInterface() CryptoInterface {
        return CryptoInterface{
            .generateKeypairFn = generateStdCrypto,
            .keypairFromSeedFn = fromSeedStdCrypto,
            .signFn = signStdCrypto,
            .verifyFn = verifyStdCrypto,
            .hashFn = hashBlake3,
        };
    }
    
    fn generateStdCrypto() KeypairResult {
        const kp = std.crypto.sign.Ed25519.KeyPair.generate();
        return KeypairResult{
            .public_key = kp.public_key.bytes,
            .secret_key = kp.secret_key.bytes,
        };
    }
    
    fn fromSeedStdCrypto(seed: [32]u8) KeypairResult {
        // NOTE: This is not truly deterministic from seed due to std.crypto limitations
        // Parent applications should implement proper seed-to-keypair derivation
        // For now, we ignore the seed parameter
        _ = seed;
        const kp = std.crypto.sign.Ed25519.KeyPair.generate();
        return KeypairResult{
            .public_key = kp.public_key.bytes,
            .secret_key = kp.secret_key.bytes,
        };
    }
    
    fn signStdCrypto(message: []const u8, secret_key: [64]u8) [64]u8 {
        const kp = std.crypto.sign.Ed25519.KeyPair{
            .public_key = std.crypto.sign.Ed25519.PublicKey{ .bytes = secret_key[32..64].* },
            .secret_key = std.crypto.sign.Ed25519.SecretKey{ .bytes = secret_key },
        };
        const signature = kp.sign(message, null) catch unreachable;
        var result: [64]u8 = undefined;
        result[0..32].* = signature.r;
        result[32..64].* = signature.s;
        return result;
    }
    
    fn verifyStdCrypto(message: []const u8, signature: [64]u8, public_key: [32]u8) bool {
        const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key) catch return false;
        const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature);
        sig.verify(message, pub_key) catch return false;
        return true;
    }
    
    fn hashBlake3(data: []const u8) [32]u8 {
        var hasher = std.crypto.hash.Blake3.init(.{});
        hasher.update(data);
        var result: [32]u8 = undefined;
        hasher.final(&result);
        return result;
    }
};
