//! Pure Zig Blake3 implementation for zsig
//! High-performance cryptographic hash function
//! Self-contained, no external dependencies

const std = @import("std");

/// Blake3 output size (32 bytes)
pub const DIGEST_SIZE = 32;

/// Blake3 hasher struct
pub const Blake3 = struct {
    hasher: std.crypto.hash.Blake3,

    /// Initialize a new Blake3 hasher
    pub fn init(options: std.crypto.hash.Blake3.Options) Blake3 {
        return Blake3{
            .hasher = std.crypto.hash.Blake3.init(options),
        };
    }

    /// Initialize with default options
    pub fn initDefault() Blake3 {
        return init(.{});
    }

    /// Update hasher with data
    pub fn update(self: *Blake3, data: []const u8) void {
        self.hasher.update(data);
    }

    /// Finalize and get digest
    pub fn final(self: *Blake3, out: *[DIGEST_SIZE]u8) void {
        self.hasher.final(out);
    }

    /// Reset hasher for reuse
    pub fn reset(self: *Blake3) void {
        self.hasher = std.crypto.hash.Blake3.init(.{});
    }
};

/// One-shot Blake3 hash function
pub fn hash(data: []const u8) [DIGEST_SIZE]u8 {
    var hasher = Blake3.initDefault();
    hasher.update(data);
    var digest: [DIGEST_SIZE]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

/// Blake3 with context/domain separation
pub fn hashWithContext(context: []const u8, data: []const u8) [DIGEST_SIZE]u8 {
    var hasher = Blake3.initDefault();

    // Add context for domain separation
    hasher.update("ZSIG_V0.5.0:");
    hasher.update(context);
    hasher.update(":");
    hasher.update(data);

    var digest: [DIGEST_SIZE]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

/// Convert digest to hex string
pub fn digestToHex(digest: [DIGEST_SIZE]u8, allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&digest)});
}

/// Parse digest from hex string
pub fn digestFromHex(hex_digest: []const u8) ![DIGEST_SIZE]u8 {
    if (hex_digest.len != DIGEST_SIZE * 2) return error.InvalidDigestLength;

    var digest: [DIGEST_SIZE]u8 = undefined;
    _ = try std.fmt.hexToBytes(&digest, hex_digest);
    return digest;
}

/// Timing-safe digest comparison
pub fn digestEqual(a: [DIGEST_SIZE]u8, b: [DIGEST_SIZE]u8) bool {
    return std.mem.eql(u8, &a, &b);
}

test "Blake3 basic functionality" {
    const testing = std.testing;

    // Test one-shot hash
    const data = "Hello, zsig Blake3!";
    const digest1 = hash(data);
    const digest2 = hash(data);

    // Same input should produce same output
    try testing.expect(digestEqual(digest1, digest2));

    // Different input should produce different output
    const different_digest = hash("Different data");
    try testing.expect(!digestEqual(digest1, different_digest));
}

test "Blake3 incremental hashing" {
    const testing = std.testing;

    const data1 = "Hello, ";
    const data2 = "zsig Blake3!";
    const combined = "Hello, zsig Blake3!";

    // Incremental hash
    var hasher = Blake3.initDefault();
    hasher.update(data1);
    hasher.update(data2);
    var incremental_digest: [DIGEST_SIZE]u8 = undefined;
    hasher.final(&incremental_digest);

    // One-shot hash
    const oneshot_digest = hash(combined);

    // Should be identical
    try testing.expect(digestEqual(incremental_digest, oneshot_digest));
}

test "Blake3 with context" {
    const testing = std.testing;

    const data = "test message";
    const context1 = "signing";
    const context2 = "verification";

    const digest1 = hashWithContext(data, context1);
    const digest2 = hashWithContext(data, context2);

    // Different contexts should produce different digests
    try testing.expect(!digestEqual(digest1, digest2));

    // Same context should produce same digest
    const digest3 = hashWithContext(data, context1);
    try testing.expect(digestEqual(digest1, digest3));
}
