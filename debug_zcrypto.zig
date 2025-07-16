const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.debug.print("Testing zcrypto v0.5.0 directly...\n", .{});
    
    // Generate a keypair directly with zcrypto
    const keypair = zcrypto.asym.ed25519.generate();
    std.debug.print("Public key: {}\n", .{std.fmt.fmtSliceHexLower(&keypair.public_key)});
    std.debug.print("Private key: {}\n", .{std.fmt.fmtSliceHexLower(&keypair.private_key)});
    std.debug.print("Private key size: {} bytes\n", .{keypair.private_key.len});
    
    // Test signing directly
    const message = "Direct zcrypto test";
    const signature = try keypair.sign(message);
    std.debug.print("Signature: {}\n", .{std.fmt.fmtSliceHexLower(&signature)});
    
    // Test verification directly
    const is_valid = keypair.verify(message, signature);
    std.debug.print("Direct verification: {}\n", .{is_valid});
    
    // Test with a new keypair for verification only
    const verify_keypair = zcrypto.asym.ed25519.KeyPair{
        .public_key = keypair.public_key,
        .private_key = undefined, // This might be the issue
    };
    const is_valid2 = verify_keypair.verify(message, signature);
    std.debug.print("Verification with undefined private key: {}\n", .{is_valid2});
    
    // Test with zero private key
    var zero_private: [64]u8 = undefined;
    @memset(&zero_private, 0);
    const verify_keypair2 = zcrypto.asym.ed25519.KeyPair{
        .public_key = keypair.public_key,
        .private_key = zero_private,
    };
    const is_valid3 = verify_keypair2.verify(message, signature);
    std.debug.print("Verification with zero private key: {}\n", .{is_valid3});
    
    _ = allocator;
}
