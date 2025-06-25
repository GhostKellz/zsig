//! Command-line interface for Zsig cryptographic operations
//! Provides keygen, sign, verify, and key management commands

const std = @import("std");
const zsig = @import("zsig.zig");
const fs = std.fs;
const print = std.debug.print;

const CliError = error{
    InvalidArguments,
    FileNotFound,
    InvalidKeyFormat,
    InvalidSignatureFormat,
    VerificationFailed,
    KeyGenerationFailed,
    FileWriteError,
    FileReadError,
};

const Command = enum {
    keygen,
    sign,
    verify,
    pubkey,
    help,
    version,
    multisig,
    hmac,
};

const Args = struct {
    command: Command,
    input_file: ?[]const u8 = null,
    output_file: ?[]const u8 = null,
    key_file: ?[]const u8 = null,
    signature_file: ?[]const u8 = null,
    public_key_file: ?[]const u8 = null,
    seed: ?[]const u8 = null,
    passphrase: ?[]const u8 = null,
    context: ?[]const u8 = null,
    format: []const u8 = "base64", // base64, hex, raw
    inline_mode: bool = false,
    verbose: bool = false,
    algorithm: []const u8 = "ed25519", // ed25519, secp256k1, secp256r1
    hmac_key: ?[]const u8 = null,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = std.process.argsAlloc(allocator) catch |err| {
        print("Error: Failed to parse arguments: {}\n", .{err});
        return;
    };
    defer std.process.argsFree(allocator, args);

    const parsed_args = parseArgs(args) catch |err| {
        switch (err) {
            CliError.InvalidArguments => {
                print("Error: Invalid arguments. Use 'zsig help' for usage information.\n", .{});
                return;
            },
            else => {
                print("Error: Failed to parse arguments: {}\n", .{err});
                return;
            },
        }
    };

    switch (parsed_args.command) {
        .keygen => try cmdKeygen(allocator, parsed_args),
        .sign => try cmdSign(allocator, parsed_args),
        .verify => try cmdVerify(allocator, parsed_args),
        .pubkey => try cmdPubkey(allocator, parsed_args),
        .help => cmdHelp(),
        .version => cmdVersion(),
        .multisig => try cmdMultisig(allocator, parsed_args),
        .hmac => try cmdHmac(allocator, parsed_args),
    }
}

fn parseArgs(args: [][:0]u8) !Args {
    if (args.len < 2) return CliError.InvalidArguments;

    const command_str = args[1];
    const command = std.meta.stringToEnum(Command, command_str) orelse return CliError.InvalidArguments;

    var parsed = Args{ .command = command };
    
    var i: usize = 2;
    while (i < args.len) : (i += 2) {
        if (i + 1 >= args.len) break;
        
        const flag = args[i];
        const value = args[i + 1];
        
        if (std.mem.eql(u8, flag, "--in") or std.mem.eql(u8, flag, "-i")) {
            parsed.input_file = value;
        } else if (std.mem.eql(u8, flag, "--out") or std.mem.eql(u8, flag, "-o")) {
            parsed.output_file = value;
        } else if (std.mem.eql(u8, flag, "--key") or std.mem.eql(u8, flag, "-k")) {
            parsed.key_file = value;
        } else if (std.mem.eql(u8, flag, "--sig") or std.mem.eql(u8, flag, "-s")) {
            parsed.signature_file = value;
        } else if (std.mem.eql(u8, flag, "--pubkey") or std.mem.eql(u8, flag, "-p")) {
            parsed.public_key_file = value;
        } else if (std.mem.eql(u8, flag, "--seed")) {
            parsed.seed = value;
        } else if (std.mem.eql(u8, flag, "--passphrase")) {
            parsed.passphrase = value;
        } else if (std.mem.eql(u8, flag, "--context")) {
            parsed.context = value;
        } else if (std.mem.eql(u8, flag, "--format")) {
            parsed.format = value;
        } else if (std.mem.eql(u8, flag, "--inline")) {
            parsed.inline_mode = true;
            i -= 1; // No value for this flag
        } else if (std.mem.eql(u8, flag, "--verbose")) {
            parsed.verbose = true;
            i -= 1; // No value for this flag
        } else if (std.mem.eql(u8, flag, "--algorithm") or std.mem.eql(u8, flag, "-a")) {
            parsed.algorithm = value;
        } else if (std.mem.eql(u8, flag, "--hmac-key")) {
            parsed.hmac_key = value;
        }
    }

    return parsed;
}

fn cmdKeygen(allocator: std.mem.Allocator, args: Args) !void {
    if (args.verbose) print("Generating Ed25519 keypair...\n", .{});

    const keypair = if (args.seed) |seed_str|
        blk: {
            if (seed_str.len != zsig.SEED_SIZE * 2) {
                print("Error: Seed must be exactly {} hex characters\n", .{zsig.SEED_SIZE * 2});
                return CliError.InvalidArguments;
            }
            var seed: [zsig.SEED_SIZE]u8 = undefined;
            _ = std.fmt.hexToBytes(&seed, seed_str) catch {
                print("Error: Invalid hex seed\n", .{});
                return CliError.InvalidArguments;
            };
            break :blk try zsig.keypairFromSeed(seed);
        }
    else if (args.passphrase) |passphrase|
        try zsig.keypairFromPassphrase(allocator, passphrase, null)
    else
        try zsig.generateKeypair(allocator);

    // Generate output files
    const base_name = args.output_file orelse "zsig_key";
    
    // Write private key file (.key)
    const key_filename = try std.fmt.allocPrint(allocator, "{s}.key", .{base_name});
    defer allocator.free(key_filename);
    
    const key_bundle = try keypair.exportBundle(allocator);
    defer allocator.free(key_bundle);
    
    try writeFile(key_filename, key_bundle);
    
    // Write public key file (.pub)
    const pub_filename = try std.fmt.allocPrint(allocator, "{s}.pub", .{base_name});
    defer allocator.free(pub_filename);
    
    const pub_hex = try keypair.publicKeyHex(allocator);
    defer allocator.free(pub_hex);
    
    try writeFile(pub_filename, pub_hex);
    
    if (args.verbose) {
        print("Generated keypair:\n", .{});
        print("  Private key: {s}\n", .{key_filename});
        print("  Public key: {s}\n", .{pub_filename});
        print("  Public key (hex): {s}\n", .{pub_hex});
    } else {
        print("Keypair generated: {s}.key, {s}.pub\n", .{ base_name, base_name });
    }
}

fn cmdSign(allocator: std.mem.Allocator, args: Args) !void {
    const input_file = args.input_file orelse {
        print("Error: Input file required (--in)\n", .{});
        return CliError.InvalidArguments;
    };
    
    const key_file = args.key_file orelse {
        print("Error: Key file required (--key)\n", .{});
        return CliError.InvalidArguments;
    };

    if (args.verbose) print("Reading message from {s}...\n", .{input_file});
    const message = readFile(allocator, input_file) catch |err| {
        print("Error reading input file: {}\n", .{err});
        return CliError.FileReadError;
    };
    defer allocator.free(message);

    if (args.verbose) print("Loading keypair from {s}...\n", .{key_file});
    const keypair = try loadKeypair(allocator, key_file);

    if (args.verbose) print("Signing message...\n", .{});
    const signature = if (args.context) |context|
        try zsig.signWithContext(message, context, keypair)
    else
        try zsig.signMessage(message, keypair);

    // Output signature
    if (args.inline_mode) {
        const inline_sig = try zsig.signInline(allocator, message, keypair);
        defer allocator.free(inline_sig);
        
        const output_file = args.output_file orelse "signed_message";
        try writeFile(output_file, inline_sig);
        
        if (args.verbose) {
            print("Inline signature written to {s}\n", .{output_file});
        } else {
            print("Signed: {s}\n", .{output_file});
        }
    } else {
        const sig_data = if (std.mem.eql(u8, args.format, "hex"))
            try signature.toHex(allocator)
        else if (std.mem.eql(u8, args.format, "base64"))
            try signature.toBase64(allocator)
        else if (std.mem.eql(u8, args.format, "raw"))
            try allocator.dupe(u8, &signature.bytes)
        else {
            print("Error: Invalid format. Use hex, base64, or raw\n", .{});
            return CliError.InvalidArguments;
        };
        defer allocator.free(sig_data);

        const output_file = args.output_file orelse 
            try std.fmt.allocPrint(allocator, "{s}.sig", .{input_file});
        defer if (args.output_file == null) allocator.free(output_file);
        
        try writeFile(output_file, sig_data);
        
        if (args.verbose) {
            print("Signature ({s}) written to {s}\n", .{ args.format, output_file });
        } else {
            print("Signed: {s}\n", .{output_file});
        }
    }
}

fn cmdVerify(allocator: std.mem.Allocator, args: Args) !void {
    if (args.inline_mode) {
        const input_file = args.input_file orelse {
            print("Error: Input file required (--in)\n", .{});
            return CliError.InvalidArguments;
        };
        
        const public_key_file = args.public_key_file orelse {
            print("Error: Public key file required (--pubkey)\n", .{});
            return CliError.InvalidArguments;
        };

        const signed_message = try readFile(allocator, input_file);
        defer allocator.free(signed_message);
        
        const public_key = try loadPublicKey(allocator, public_key_file);
        
        const is_valid = zsig.verifyInline(signed_message, &public_key);
        
        if (is_valid) {
            print("✓ Signature valid\n", .{});
            if (args.verbose) {
                const extracted = zsig.verify.extractMessage(signed_message);
                print("Message: {s}\n", .{extracted});
            }
        } else {
            print("✗ Signature invalid\n", .{});
            return CliError.VerificationFailed;
        }
    } else {
        const input_file = args.input_file orelse {
            print("Error: Input file required (--in)\n", .{});
            return CliError.InvalidArguments;
        };
        
        const signature_file = args.signature_file orelse {
            print("Error: Signature file required (--sig)\n", .{});
            return CliError.InvalidArguments;
        };
        
        const public_key_file = args.public_key_file orelse {
            print("Error: Public key file required (--pubkey)\n", .{});
            return CliError.InvalidArguments;
        };

        const message = try readFile(allocator, input_file);
        defer allocator.free(message);
        
        const signature_data = try readFile(allocator, signature_file);
        defer allocator.free(signature_data);
        
        const public_key = try loadPublicKey(allocator, public_key_file);

        // Decode signature based on format (default is base64)
        const signature_bytes = if (std.mem.eql(u8, args.format, "hex")) blk: {
            const sig = try zsig.sign.Signature.fromHex(signature_data);
            break :blk sig.bytes;
        } else if (std.mem.eql(u8, args.format, "raw")) blk: {
            if (signature_data.len != zsig.SIGNATURE_SIZE) {
                print("Error: Raw signature must be exactly 64 bytes\n", .{});
                return CliError.InvalidSignatureFormat;
            }
            break :blk signature_data[0..zsig.SIGNATURE_SIZE].*;
        } else blk: {
            // Default: base64
            const sig = try zsig.sign.Signature.fromBase64(signature_data);
            break :blk sig.bytes;
        };

        const is_valid = if (args.context) |context|
            zsig.verifyWithContext(message, context, &signature_bytes, &public_key)
        else
            zsig.verifySignature(message, &signature_bytes, &public_key);

        if (is_valid) {
            print("✓ Signature valid\n", .{});
        } else {
            print("✗ Signature invalid\n", .{});
            return CliError.VerificationFailed;
        }
    }
}

fn cmdPubkey(allocator: std.mem.Allocator, args: Args) !void {
    const key_file = args.key_file orelse {
        print("Error: Key file required (--key)\n", .{});
        return CliError.InvalidArguments;
    };

    const keypair = try loadKeypair(allocator, key_file);
    const pub_hex = try keypair.publicKeyHex(allocator);
    defer allocator.free(pub_hex);

    if (args.output_file) |output| {
        try writeFile(output, pub_hex);
        print("Public key written to {s}\n", .{output});
    } else {
        print("{s}\n", .{pub_hex});
    }
}

fn cmdHelp() void {
    print(
        \\Zsig v{s} - Cryptographic Signing Engine for Zig
        \\
        \\USAGE:
        \\    zsig <COMMAND> [OPTIONS]
        \\
        \\COMMANDS:
        \\    keygen      Generate a new Ed25519 keypair
        \\    sign        Sign a message or file
        \\    verify      Verify a signature
        \\    pubkey      Extract public key from private key file
        \\    multisig    Multi-algorithm signing (Ed25519, secp256k1, secp256r1)
        \\    hmac        HMAC authenticated signing
        \\    help        Show this help message
        \\    version     Show version information
        \\
        \\KEYGEN OPTIONS:
        \\    --out <file>        Output filename prefix (default: zsig_key)
        \\    --seed <hex>        Use specific 64-char hex seed (deterministic)
        \\    --passphrase <str>  Generate from passphrase (deterministic)
        \\
        \\SIGN OPTIONS:
        \\    --in <file>         Input file to sign
        \\    --key <file>        Private key file (.key)
        \\    --out <file>        Output signature file (default: input.sig)
        \\    --context <str>     Additional context for domain separation
        \\    --format <fmt>      Output format: base64, hex, raw (default: base64)
        \\    --inline            Create inline signature (message + signature)
        \\
        \\VERIFY OPTIONS:
        \\    --in <file>         Input file (message or inline signature)
        \\    --sig <file>        Signature file (not needed with --inline)
        \\    --pubkey <file>     Public key file (.pub)
        \\    --context <str>     Context used during signing
        \\    --inline            Verify inline signature
        \\
        \\MULTISIG OPTIONS:
        \\    --in <file>         Input file to sign/verify
        \\    --algorithm <alg>   Algorithm: ed25519, secp256k1, secp256r1 (default: ed25519)
        \\    --seed <hex>        64-char hex seed for deterministic key generation
        \\    --key <any>         Enable signing mode (generates new keypair)
        \\    --sig <file>        Signature file for verification
        \\    --pubkey <file>     Public key file for verification
        \\    --out <file>        Output filename (default: multisig.sig)
        \\    --verbose           Verbose output
        \\
        \\HMAC OPTIONS:
        \\    --in <file>         Input file to sign/verify
        \\    --hmac-key <key>    HMAC authentication key (required)
        \\    --algorithm <alg>   Algorithm: ed25519, secp256k1, secp256r1 (default: ed25519)
        \\    --seed <hex>        64-char hex seed for deterministic key generation
        \\    --key <any>         Enable signing mode (generates new keypair)
        \\    --sig <file>        HMAC signature file for verification
        \\    --out <file>        Output filename (default: hmac_auth.sig)
        \\    --verbose           Verbose output
        \\
        \\EXAMPLES:
        \\    # Classic Ed25519 signing
        \\    zsig keygen --out alice
        \\    zsig sign --in message.txt --key alice.key
        \\    zsig verify --in message.txt --sig message.txt.sig --pubkey alice.pub
        \\    
        \\    # Bitcoin-style secp256k1 signing
        \\    zsig multisig --in tx.hash --algorithm secp256k1 --key new --out bitcoin.sig
        \\    zsig multisig --in tx.hash --algorithm secp256k1 --sig bitcoin.sig --pubkey bitcoin.sig.pub
        \\    
        \\    # HMAC authenticated signing
        \\    zsig hmac --in sensitive.doc --hmac-key mypassword --algorithm ed25519 --key new
        \\    zsig hmac --in sensitive.doc --hmac-key mypassword --sig hmac_auth.sig
        \\    
        \\    # Deterministic key generation from seed
        \\    zsig multisig --in wallet.json --algorithm secp256k1 --seed 0123456789abcdef... --key new
        \\
    , .{zsig.version});
}

fn cmdVersion() void {
    print("Zsig v{s}\n", .{zsig.version});
    print("Multi-algorithm cryptographic signing engine for Zig\n", .{});
    print("Powered by zcrypto v0.2.0\n", .{});
    print("\nSupported algorithms:\n");
    print("  • Ed25519 (default) - Fast, secure, deterministic\n");
    print("  • secp256k1 - Bitcoin/Ethereum compatible\n");
    print("  • secp256r1 (P-256) - NIST standard\n");
    print("\nSecurity features:\n");
    print("  • HMAC authentication\n");
    print("  • Constant-time operations\n");
    print("  • Deterministic key derivation\n");
    print("  • Context-separated signing\n");
    print("  • Secure memory clearing\n");
    print("\nFeatures: CLI, WASM, multi-algorithm, HMAC auth, zwallet compatible\n");
    print("Author: {s}\n", .{zsig.info.author});
    print("License: {s}\n", .{zsig.info.license});
}

// Utility functions

fn readFile(allocator: std.mem.Allocator, filename: []const u8) ![]u8 {
    const file = fs.cwd().openFile(filename, .{}) catch return CliError.FileNotFound;
    defer file.close();
    
    const file_size = try file.getEndPos();
    const contents = try allocator.alloc(u8, file_size);
    _ = try file.readAll(contents);
    
    return contents;
}

fn writeFile(filename: []const u8, data: []const u8) !void {
    const file = fs.cwd().createFile(filename, .{}) catch return CliError.FileWriteError;
    defer file.close();
    
    try file.writeAll(data);
}

fn loadKeypair(allocator: std.mem.Allocator, filename: []const u8) !zsig.Keypair {
    const contents = try readFile(allocator, filename);
    defer allocator.free(contents);
    
    // Parse the key bundle format
    const private_start = "Private: ";
    const private_start_idx = std.mem.indexOf(u8, contents, private_start) orelse
        return CliError.InvalidKeyFormat;
    
    const private_data_start = private_start_idx + private_start.len;
    const private_end_idx = std.mem.indexOf(u8, contents[private_data_start..], "\n") orelse
        return CliError.InvalidKeyFormat;
    
    const private_b64 = contents[private_data_start..private_data_start + private_end_idx];
    
    return zsig.Keypair.fromPrivateKeyBase64(private_b64) catch CliError.InvalidKeyFormat;
}

fn loadPublicKey(allocator: std.mem.Allocator, filename: []const u8) ![zsig.PUBLIC_KEY_SIZE]u8 {
    const contents = try readFile(allocator, filename);
    defer allocator.free(contents);
    
    // Remove newlines and whitespace
    var clean_hex = std.ArrayList(u8).init(allocator);
    defer clean_hex.deinit();
    
    for (contents) |char| {
        if (std.ascii.isAlphanumeric(char)) {
            try clean_hex.append(char);
        }
    }
    
    return zsig.Keypair.publicKeyFromHex(clean_hex.items) catch CliError.InvalidKeyFormat;
}

fn algorithmFromString(algorithm_str: []const u8) !zsig.SignatureAlgorithm {
    if (std.mem.eql(u8, algorithm_str, "ed25519")) return .ed25519;
    if (std.mem.eql(u8, algorithm_str, "secp256k1")) return .secp256k1;
    if (std.mem.eql(u8, algorithm_str, "secp256r1")) return .secp256r1;
    return CliError.InvalidArguments;
}

fn cmdMultisig(allocator: std.mem.Allocator, args: Args) !void {
    const algorithm = try algorithmFromString(args.algorithm);
    
    if (args.verbose) print("Multi-algorithm operation with {s}...\n", .{args.algorithm});
    
    if (args.input_file == null) {
        print("Error: Input file required for multisig operations\n");
        return CliError.InvalidArguments;
    }
    
    const message = try readFile(allocator, args.input_file.?);
    defer allocator.free(message);
    
    if (args.key_file != null) {
        // Signing mode
        if (args.verbose) print("Signing with {s}...\n", .{args.algorithm});
        
        // For multisig, we need to generate a new keypair or load from seed
        const keypair = if (args.seed) |seed_str| blk: {
            if (seed_str.len != 64) {
                print("Error: Seed must be exactly 64 hex characters\n");
                return CliError.InvalidArguments;
            }
            var seed: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&seed, seed_str) catch {
                print("Error: Invalid hex seed\n");
                return CliError.InvalidArguments;
            };
            break :blk try zsig.MultiSig.keypairFromSeed(algorithm, seed);
        } else {
            break :blk try zsig.MultiSig.generateKeypair(algorithm);
        };
        
        const signature = zsig.MultiSig.sign(message, keypair);
        const public_key = keypair.publicKey();
        
        // Save signature
        const sig_hex = try std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&signature)});
        defer allocator.free(sig_hex);
        
        const sig_filename = args.output_file orelse "multisig.sig";
        try writeFile(sig_filename, sig_hex);
        
        // Save public key
        const pub_hex = try std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&public_key)});
        defer allocator.free(pub_hex);
        
        const pub_filename = try std.fmt.allocPrint(allocator, "{s}.pub", .{sig_filename});
        defer allocator.free(pub_filename);
        try writeFile(pub_filename, pub_hex);
        
        if (args.verbose) {
            print("Signature saved to: {s}\n", .{sig_filename});
            print("Public key saved to: {s}\n", .{pub_filename});
        }
        
    } else if (args.signature_file != null and args.public_key_file != null) {
        // Verification mode
        if (args.verbose) print("Verifying with {s}...\n", .{args.algorithm});
        
        const sig_content = try readFile(allocator, args.signature_file.?);
        defer allocator.free(sig_content);
        
        const pub_content = try readFile(allocator, args.public_key_file.?);
        defer allocator.free(pub_content);
        
        // Clean hex strings
        var clean_sig = std.ArrayList(u8).init(allocator);
        defer clean_sig.deinit();
        var clean_pub = std.ArrayList(u8).init(allocator);
        defer clean_pub.deinit();
        
        for (sig_content) |char| {
            if (std.ascii.isAlphanumeric(char)) try clean_sig.append(char);
        }
        for (pub_content) |char| {
            if (std.ascii.isAlphanumeric(char)) try clean_pub.append(char);
        }
        
        if (clean_sig.items.len != 128) {
            print("Error: Invalid signature length\n");
            return CliError.InvalidSignatureFormat;
        }
        
        if (clean_pub.items.len != 64) {
            print("Error: Invalid public key length\n");
            return CliError.InvalidKeyFormat;
        }
        
        var signature: [64]u8 = undefined;
        var public_key: [32]u8 = undefined;
        
        _ = std.fmt.hexToBytes(&signature, clean_sig.items) catch {
            print("Error: Invalid signature hex\n");
            return CliError.InvalidSignatureFormat;
        };
        
        _ = std.fmt.hexToBytes(&public_key, clean_pub.items) catch {
            print("Error: Invalid public key hex\n");
            return CliError.InvalidKeyFormat;
        };
        
        const is_valid = zsig.MultiSig.verify(message, signature, public_key, algorithm);
        
        if (is_valid) {
            print("✓ Signature verification successful\n");
        } else {
            print("✗ Signature verification failed\n");
            return CliError.VerificationFailed;
        }
    } else {
        print("Error: For multisig, provide either --key for signing or --sig and --pubkey for verification\n");
        return CliError.InvalidArguments;
    }
}

fn cmdHmac(allocator: std.mem.Allocator, args: Args) !void {
    const algorithm = try algorithmFromString(args.algorithm);
    
    if (args.verbose) print("HMAC authentication with {s}...\n", .{args.algorithm});
    
    if (args.input_file == null) {
        print("Error: Input file required for HMAC operations\n");
        return CliError.InvalidArguments;
    }
    
    if (args.hmac_key == null) {
        print("Error: HMAC key required (use --hmac-key)\n");
        return CliError.InvalidArguments;
    }
    
    const message = try readFile(allocator, args.input_file.?);
    defer allocator.free(message);
    
    const hmac_key = args.hmac_key.?;
    
    if (args.key_file != null) {
        // Signing with HMAC mode
        if (args.verbose) print("Signing with HMAC authentication...\n");
        
        const keypair = if (args.seed) |seed_str| blk: {
            if (seed_str.len != 64) {
                print("Error: Seed must be exactly 64 hex characters\n");
                return CliError.InvalidArguments;
            }
            var seed: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&seed, seed_str) catch {
                print("Error: Invalid hex seed\n");
                return CliError.InvalidArguments;
            };
            break :blk try zsig.MultiSig.keypairFromSeed(algorithm, seed);
        } else {
            break :blk try zsig.MultiSig.generateKeypair(algorithm);
        };
        
        const auth_result = zsig.MultiSig.signWithHmac(message, keypair, hmac_key);
        const public_key = keypair.publicKey();
        
        // Save signature and HMAC tag
        const output_data = try std.fmt.allocPrint(allocator,
            "signature:{}\nhmac:{}\npubkey:{}\nalgorithm:{s}\n",
            .{
                std.fmt.fmtSliceHexLower(&auth_result.signature),
                std.fmt.fmtSliceHexLower(&auth_result.hmac_tag),
                std.fmt.fmtSliceHexLower(&public_key),
                args.algorithm,
            }
        );
        defer allocator.free(output_data);
        
        const output_filename = args.output_file orelse "hmac_auth.sig";
        try writeFile(output_filename, output_data);
        
        if (args.verbose) {
            print("HMAC authenticated signature saved to: {s}\n", .{output_filename});
        }
        
    } else if (args.signature_file != null) {
        // Verification with HMAC mode
        if (args.verbose) print("Verifying HMAC authenticated signature...\n");
        
        const sig_content = try readFile(allocator, args.signature_file.?);
        defer allocator.free(sig_content);
        
        // Parse the signature file
        var signature: [64]u8 = undefined;
        var hmac_tag: [32]u8 = undefined;
        var public_key: [32]u8 = undefined;
        var file_algorithm: ?zsig.SignatureAlgorithm = null;
        
        var lines = std.mem.split(u8, sig_content, "\n");
        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "signature:")) {
                const hex_sig = line[10..];
                if (hex_sig.len == 128) {
                    _ = std.fmt.hexToBytes(&signature, hex_sig) catch {
                        print("Error: Invalid signature hex\n");
                        return CliError.InvalidSignatureFormat;
                    };
                }
            } else if (std.mem.startsWith(u8, line, "hmac:")) {
                const hex_hmac = line[5..];
                if (hex_hmac.len == 64) {
                    _ = std.fmt.hexToBytes(&hmac_tag, hex_hmac) catch {
                        print("Error: Invalid HMAC hex\n");
                        return CliError.InvalidSignatureFormat;
                    };
                }
            } else if (std.mem.startsWith(u8, line, "pubkey:")) {
                const hex_pub = line[7..];
                if (hex_pub.len == 64) {
                    _ = std.fmt.hexToBytes(&public_key, hex_pub) catch {
                        print("Error: Invalid public key hex\n");
                        return CliError.InvalidKeyFormat;
                    };
                }
            } else if (std.mem.startsWith(u8, line, "algorithm:")) {
                const alg_str = line[10..];
                file_algorithm = algorithmFromString(alg_str) catch null;
            }
        }
        
        const verify_algorithm = file_algorithm orelse algorithm;
        
        const is_valid = zsig.MultiSig.verifyWithHmac(
            message,
            signature,
            hmac_tag,
            public_key,
            hmac_key,
            verify_algorithm
        );
        
        if (is_valid) {
            print("✓ HMAC authenticated signature verification successful\n");
        } else {
            print("✗ HMAC authenticated signature verification failed\n");
            return CliError.VerificationFailed;
        }
    } else {
        print("Error: For HMAC auth, provide either --key for signing or --sig for verification\n");
        return CliError.InvalidArguments;
    }
}
