# 🔌 ZCRYPTO v0.5.0 API REFERENCE

**Complete API Documentation for Post-Quantum Cryptographic Library**

---

## 📋 **TABLE OF CONTENTS**

1. [Quick Start](#quick-start)
2. [Core Cryptographic Primitives](#core-cryptographic-primitives)
3. [Post-Quantum Algorithms](#post-quantum-algorithms)
4. [QUIC Cryptography](#quic-cryptography)
5. [TLS Integration](#tls-integration)
6. [Foreign Function Interface](#foreign-function-interface)
7. [Usage Examples](#usage-examples)
8. [Error Handling](#error-handling)
9. [Integration Patterns](#integration-patterns)

---

## 🚀 **QUICK START**

### **Installation & Build**

```bash
# Add zcrypto as a dependency
zig fetch --save git+https://github.com/ghostkellz/zcrypto.git

# Or include directly in build.zig
const zcrypto = b.dependency("zcrypto", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zcrypto", zcrypto.module("zcrypto"));
```

### **Basic Usage**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub fn main() !void {
    // Hash some data
    const message = "Hello, zcrypto!";
    const hash = zcrypto.hash.sha256(message);
    
    // Generate Ed25519 key pair
    const keypair = zcrypto.asym.ed25519.generate();
    
    // Sign a message
    const signature = try keypair.sign(message);
    const is_valid = keypair.verify(message, signature);
    
    std.debug.print("Message: {s}\n", .{message});
    std.debug.print("Signature valid: {}\n", .{is_valid});
}
```

---

## 🔑 **CORE CRYPTOGRAPHIC PRIMITIVES**

### **Hash Functions**

#### `zcrypto.hash`

```zig
pub const hash = struct {
    /// SHA-256 hash function (32 bytes output)
    pub fn sha256(input: []const u8) [32]u8;
    
    /// BLAKE2b hash function (64 bytes output)
    pub fn blake2b(input: []const u8) [64]u8;
    
    /// Convert hash to hex string
    pub fn toHex(comptime T: type, hash_bytes: T, buffer: []u8) []u8;
};
```

**Example:**
```zig
const data = "Sign this data";
const digest = zcrypto.hash.sha256(data);

// Convert to hex for display
var hex_buf: [64]u8 = undefined;
const hex = zcrypto.hash.toHex([32]u8, digest, &hex_buf);
std.debug.print("SHA-256: {s}\n", .{hex});
```

### **Asymmetric Cryptography**

#### `zcrypto.asym.ed25519`

```zig
pub const ed25519 = struct {
    pub const KeyPair = struct {
        public_key: [32]u8,
        private_key: [32]u8,
        
        /// Generate new Ed25519 key pair
        pub fn generate() KeyPair;
        
        /// Sign a message
        pub fn sign(self: *const KeyPair, message: []const u8) ![64]u8;
        
        /// Verify signature
        pub fn verify(self: *const KeyPair, message: []const u8, signature: [64]u8) bool;
    };
};
```

**Example:**
```zig
// Generate keys for your signing service
const signing_keys = zcrypto.asym.ed25519.generate();

// Sign transaction data
const tx_data = "transfer 100 tokens to alice";
const signature = try signing_keys.sign(tx_data);

// Verify signature
const is_valid = signing_keys.verify(tx_data, signature);
std.debug.print("Transaction signature valid: {}\n", .{is_valid});
```

### **Symmetric Cryptography**

#### `zcrypto.sym`

```zig
pub const sym = struct {
    pub const EncryptedData = struct {
        data: []u8,
        tag: [16]u8,
        
        pub fn deinit(self: EncryptedData) void;
    };
    
    /// AES-128-GCM encryption
    pub fn encryptAes128Gcm(
        allocator: std.mem.Allocator,
        key: [16]u8,
        nonce: [12]u8,
        plaintext: []const u8,
        aad: []const u8
    ) !EncryptedData;
    
    /// AES-128-GCM decryption
    pub fn decryptAes128Gcm(
        allocator: std.mem.Allocator,
        key: [16]u8,
        nonce: [12]u8,
        ciphertext: []const u8,
        tag: [16]u8,
        aad: []const u8
    ) !?[]u8;
};
```

**Example:**
```zig
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
defer _ = gpa.deinit();
const allocator = gpa.allocator();

// Encrypt sensitive data
const key = zcrypto.rand.randomArray(16);
const nonce = zcrypto.rand.randomArray(12);
const secret_message = "API key: sk_1234567890";

const encrypted = try zcrypto.sym.encryptAes128Gcm(
    allocator, key, nonce, secret_message, "metadata"
);
defer encrypted.deinit();

// Decrypt later
const decrypted = try zcrypto.sym.decryptAes128Gcm(
    allocator, key, nonce, encrypted.data, encrypted.tag, "metadata"
);
defer if (decrypted) |d| allocator.free(d);
```

### **Key Derivation**

#### `zcrypto.kdf`

```zig
pub const kdf = struct {
    /// Derive key using HKDF
    pub fn deriveKey(
        allocator: std.mem.Allocator,
        input_key_material: []const u8,
        info: []const u8,
        length: usize
    ) ![]u8;
};
```

**Example:**
```zig
// Derive application-specific keys
const master_secret = "shared-master-secret";
const api_key = try zcrypto.kdf.deriveKey(
    allocator, master_secret, "api-encryption", 32
);
defer allocator.free(api_key);

const db_key = try zcrypto.kdf.deriveKey(
    allocator, master_secret, "database-encryption", 32
);
defer allocator.free(db_key);
```

### **Random Generation**

#### `zcrypto.rand`

```zig
pub const rand = struct {
    /// Generate random array of specified size
    pub fn randomArray(comptime size: usize) [size]u8;
    
    /// Generate random bytes
    pub fn randomBytes(allocator: std.mem.Allocator, size: usize) ![]u8;
};
```

---

## 🌌 **POST-QUANTUM ALGORITHMS**

### **ML-KEM (Key Encapsulation)**

#### `zcrypto.pq.ml_kem.ML_KEM_768`

```zig
pub const ML_KEM_768 = struct {
    pub const PUBLIC_KEY_SIZE = 1184;
    pub const PRIVATE_KEY_SIZE = 2400;
    pub const CIPHERTEXT_SIZE = 1088;
    pub const SHARED_SECRET_SIZE = 32;
    
    pub const KeyPair = struct {
        public_key: [PUBLIC_KEY_SIZE]u8,
        private_key: [PRIVATE_KEY_SIZE]u8,
        
        /// Generate ML-KEM-768 key pair
        pub fn generate(seed: [32]u8) !KeyPair;
        
        /// Generate with random seed
        pub fn generateRandom() !KeyPair;
        
        /// Encapsulate shared secret
        pub fn encapsulate(
            public_key: [PUBLIC_KEY_SIZE]u8,
            randomness: [32]u8
        ) !struct {
            ciphertext: [CIPHERTEXT_SIZE]u8,
            shared_secret: [SHARED_SECRET_SIZE]u8,
        };
        
        /// Decapsulate shared secret
        pub fn decapsulate(
            self: *const KeyPair,
            ciphertext: [CIPHERTEXT_SIZE]u8
        ) ![SHARED_SECRET_SIZE]u8;
    };
};
```

**Example:**
```zig
// Generate post-quantum key pair for secure communication
const pq_keys = try zcrypto.pq.ml_kem.ML_KEM_768.KeyPair.generateRandom();

// Client: encapsulate shared secret
var randomness: [32]u8 = undefined;
std.crypto.random.bytes(&randomness);

const encaps_result = try zcrypto.pq.ml_kem.ML_KEM_768.KeyPair.encapsulate(
    pq_keys.public_key, randomness
);

// Server: decapsulate shared secret
const shared_secret = try pq_keys.decapsulate(encaps_result.ciphertext);

// Both sides now have the same shared secret
std.debug.print("Shared secret established: {} bytes\n", .{shared_secret.len});
```

### **ML-DSA (Digital Signatures)**

#### `zcrypto.pq.ml_dsa.ML_DSA_65`

```zig
pub const ML_DSA_65 = struct {
    pub const PUBLIC_KEY_SIZE = 1952;
    pub const PRIVATE_KEY_SIZE = 4016;
    pub const SIGNATURE_SIZE = 3309;
    
    pub const KeyPair = struct {
        public_key: [PUBLIC_KEY_SIZE]u8,
        private_key: [PRIVATE_KEY_SIZE]u8,
        
        /// Generate ML-DSA-65 key pair
        pub fn generate(seed: [32]u8) !KeyPair;
        
        /// Generate with random seed
        pub fn generateRandom(allocator: std.mem.Allocator) !KeyPair;
        
        /// Sign message
        pub fn sign(
            self: *const KeyPair,
            message: []const u8,
            randomness: [32]u8
        ) ![SIGNATURE_SIZE]u8;
        
        /// Verify signature (static method)
        pub fn verify(
            public_key: [PUBLIC_KEY_SIZE]u8,
            message: []const u8,
            signature: [SIGNATURE_SIZE]u8
        ) !bool;
    };
};
```

**Example:**
```zig
// Generate post-quantum signing keys
const pq_signer = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.generateRandom(allocator);

// Sign important document
const document = "Certificate of Authenticity: Quantum-Safe Document v1.0";
var signing_randomness: [32]u8 = undefined;
std.crypto.random.bytes(&signing_randomness);

const pq_signature = try pq_signer.sign(document, signing_randomness);

// Verify signature
const is_valid = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.verify(
    pq_signer.public_key, document, pq_signature
);
std.debug.print("Post-quantum signature valid: {}\n", .{is_valid});
```

### **Hybrid Cryptography**

#### `zcrypto.pq.hybrid.X25519_ML_KEM_768`

```zig
pub const X25519_ML_KEM_768 = struct {
    pub const HybridKeyPair = struct {
        classical_public: [32]u8,
        classical_private: [32]u8,
        pq_public: [1184]u8,
        pq_private: [2400]u8,
        
        /// Generate hybrid key pair
        pub fn generate() !HybridKeyPair;
        
        /// Perform hybrid key exchange
        pub fn exchange(
            self: *const HybridKeyPair,
            peer_classical: [32]u8,
            peer_pq_ciphertext: [1088]u8
        ) ![64]u8; // Combined 64-byte shared secret
    };
};
```

**Example:**
```zig
// Generate hybrid keys for maximum security
const alice_keys = try zcrypto.pq.hybrid.X25519_ML_KEM_768.HybridKeyPair.generate();
const bob_keys = try zcrypto.pq.hybrid.X25519_ML_KEM_768.HybridKeyPair.generate();

// Alice: create key exchange material for Bob
var randomness: [32]u8 = undefined;
std.crypto.random.bytes(&randomness);

const encaps_result = try zcrypto.pq.ml_kem.ML_KEM_768.KeyPair.encapsulate(
    bob_keys.pq_public, randomness
);

// Bob: perform hybrid key exchange
const shared_secret = try bob_keys.exchange(
    alice_keys.classical_public,
    encaps_result.ciphertext
);

std.debug.print("Hybrid shared secret: {} bytes\n", .{shared_secret.len});
```

---

## 🌐 **QUIC CRYPTOGRAPHY**

### **QuicCrypto**

#### `zcrypto.quic.QuicCrypto`

```zig
pub const QuicCrypto = struct {
    /// Initialize QUIC crypto context
    pub fn init(cipher_suite: CipherSuite) QuicCrypto;
    
    /// Derive initial keys from connection ID
    pub fn deriveInitialKeys(
        self: *QuicCrypto,
        connection_id: []const u8
    ) QuicError!void;
    
    /// Encrypt QUIC packet
    pub fn encryptPacket(
        self: *const QuicCrypto,
        level: EncryptionLevel,
        is_server: bool,
        packet_number: u64,
        header: []const u8,
        payload: []const u8,
        output: []u8
    ) QuicError!usize;
    
    /// Decrypt QUIC packet
    pub fn decryptPacket(
        self: *const QuicCrypto,
        level: EncryptionLevel,
        is_server: bool,
        packet_number: u64,
        header: []const u8,
        ciphertext: []const u8,
        output: []u8
    ) QuicError!usize;
};

pub const CipherSuite = enum {
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_ML_KEM_768_X25519_AES256_GCM_SHA384,  // Post-quantum hybrid
};

pub const EncryptionLevel = enum {
    initial,
    early_data,    // 0-RTT
    handshake,
    application,   // 1-RTT
};
```

**Example:**
```zig
// Initialize QUIC crypto for your networking service
var quic_crypto = zcrypto.quic.QuicCrypto.init(.TLS_AES_256_GCM_SHA384);

// Derive initial keys
const connection_id = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 };
try quic_crypto.deriveInitialKeys(&connection_id);

// Encrypt packet
const header = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01 };
const payload = "QUIC handshake data";
var encrypted_packet: [1500]u8 = undefined;

const encrypted_len = try quic_crypto.encryptPacket(
    .initial,
    false, // client-side
    1,     // packet number
    &header,
    payload,
    &encrypted_packet
);

std.debug.print("Encrypted QUIC packet: {} bytes\n", .{encrypted_len});
```

### **Zero-Copy Operations**

#### `zcrypto.quic.ZeroCopy`

```zig
pub const ZeroCopy = struct {
    /// In-place packet encryption for high performance
    pub fn encryptInPlace(
        crypto: *const QuicCrypto,
        level: EncryptionLevel,
        is_server: bool,
        packet_number: u64,
        packet: []u8,
        header_len: usize
    ) QuicError!void;
    
    /// In-place packet decryption
    pub fn decryptInPlace(
        crypto: *const QuicCrypto,
        level: EncryptionLevel,
        is_server: bool,
        packet_number: u64,
        packet: []u8,
        header_len: usize
    ) QuicError!usize;
};
```

**Example:**
```zig
// High-performance packet processing
var packet = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x01 } ++ "Data payload".*;
const header_len = 5;
const packet_number = 42;

// Encrypt in-place (zero-copy)
try zcrypto.quic.ZeroCopy.encryptInPlace(
    &quic_crypto, .application, false, packet_number, &packet, header_len
);

// Later: decrypt in-place
const payload_len = try zcrypto.quic.ZeroCopy.decryptInPlace(
    &quic_crypto, .application, false, packet_number, &packet, header_len
);

std.debug.print("Decrypted payload: {} bytes\n", .{payload_len});
```

---

## 🔗 **TLS INTEGRATION**

### **TLS Configuration**

#### `zcrypto.tls.config.TlsConfig`

```zig
pub const TlsConfig = struct {
    server_name: ?[]const u8,
    alpn_protocols: ?[][]const u8,
    insecure_skip_verify: bool,
    
    /// Initialize TLS configuration
    pub fn init(allocator: std.mem.Allocator) TlsConfig;
    
    /// Set server name for SNI
    pub fn withServerName(self: TlsConfig, name: []const u8) TlsConfig;
    
    /// Set ALPN protocols
    pub fn withALPN(self: TlsConfig, protocols: [][]const u8) TlsConfig;
    
    /// Skip certificate verification (insecure)
    pub fn withInsecureSkipVerify(self: TlsConfig, skip: bool) TlsConfig;
    
    /// Validate configuration
    pub fn validate(self: *const TlsConfig) !void;
    
    /// Cleanup
    pub fn deinit(self: TlsConfig) void;
};
```

**Example:**
```zig
// Configure TLS for your service
const alpn_protocols = [_][]const u8{ "h2", "http/1.1" };
const tls_config = zcrypto.tls.config.TlsConfig.init(allocator)
    .withServerName("api.myservice.com")
    .withALPN(@constCast(&alpn_protocols))
    .withInsecureSkipVerify(false);
defer tls_config.deinit();

try tls_config.validate();
std.debug.print("TLS configured for: {s}\n", .{tls_config.server_name.?});
```

### **Key Schedule**

#### `zcrypto.tls.KeySchedule`

```zig
pub const KeySchedule = struct {
    /// Initialize TLS 1.3 key schedule
    pub fn init(allocator: std.mem.Allocator, hash_algorithm: HashAlgorithm) !KeySchedule;
    
    /// Derive early secret
    pub fn deriveEarlySecret(self: *KeySchedule, psk: ?[]const u8) !void;
    
    /// Derive handshake secret
    pub fn deriveHandshakeSecret(self: *KeySchedule, ecdhe_secret: []const u8) !void;
    
    /// Derive master secret
    pub fn deriveMasterSecret(self: *KeySchedule) !void;
    
    /// Cleanup
    pub fn deinit(self: *KeySchedule) void;
};

pub const HashAlgorithm = enum { sha256, sha384 };
```

**Example:**
```zig
// TLS 1.3 key schedule for your secure protocol
var key_schedule = try zcrypto.tls.KeySchedule.init(allocator, .sha256);
defer key_schedule.deinit();

// Derive secrets step by step
try key_schedule.deriveEarlySecret(null);

const ecdhe_secret = [_]u8{0x42} ** 32; // From X25519/ML-KEM
try key_schedule.deriveHandshakeSecret(&ecdhe_secret);
try key_schedule.deriveMasterSecret();

std.debug.print("TLS 1.3 key schedule completed\n");
```

---

## 🔗 **FOREIGN FUNCTION INTERFACE**

### **C API Exports**

The library provides a complete C API for integration with other languages:

```c
// Basic types
typedef struct {
    bool success;
    uint32_t data_len;
    uint32_t error_code;
} CryptoResult;

// Hash functions
CryptoResult zcrypto_sha256(const uint8_t* input, uint32_t input_len, uint8_t* output);
CryptoResult zcrypto_blake2b(const uint8_t* input, uint32_t input_len, uint8_t* output);

// Ed25519 operations
CryptoResult zcrypto_ed25519_keygen(uint8_t* public_key, uint8_t* private_key);
CryptoResult zcrypto_ed25519_sign(
    const uint8_t* message, uint32_t message_len,
    const uint8_t* private_key,
    uint8_t* signature
);
CryptoResult zcrypto_ed25519_verify(
    const uint8_t* message, uint32_t message_len,
    const uint8_t* signature,
    const uint8_t* public_key
);

// Post-quantum operations
CryptoResult zcrypto_ml_kem_768_keygen(uint8_t* public_key, uint8_t* secret_key);
CryptoResult zcrypto_ml_kem_768_encaps(
    const uint8_t* public_key,
    uint8_t* ciphertext,
    uint8_t* shared_secret
);
CryptoResult zcrypto_ml_kem_768_decaps(
    const uint8_t* secret_key,
    const uint8_t* ciphertext,
    uint8_t* shared_secret
);

// Hybrid operations
CryptoResult zcrypto_hybrid_x25519_ml_kem_keygen(
    uint8_t* classical_public,
    uint8_t* classical_private,
    uint8_t* pq_public,
    uint8_t* pq_private
);

// QUIC operations
CryptoResult zcrypto_quic_encrypt_packet_inplace(
    const uint8_t* context,
    uint32_t level,
    bool is_server,
    uint64_t packet_number,
    uint8_t* packet,
    uint32_t packet_len,
    uint32_t header_len
);

// Utility functions
CryptoResult zcrypto_version(uint8_t* buffer, uint32_t buffer_len);
CryptoResult zcrypto_has_post_quantum(void);
CryptoResult zcrypto_get_features(uint32_t* features);
```

---

## 📝 **USAGE EXAMPLES**

### **Example 1: Digital Signature Service**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub const SignatureService = struct {
    classical_keys: zcrypto.asym.ed25519.KeyPair,
    pq_keys: zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) !SignatureService {
        const classical_keys = zcrypto.asym.ed25519.generate();
        const pq_keys = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.generateRandom(allocator);
        
        return SignatureService{
            .classical_keys = classical_keys,
            .pq_keys = pq_keys,
            .allocator = allocator,
        };
    }
    
    pub fn signDocument(self: *const SignatureService, document: []const u8) !struct {
        classical: [64]u8,
        post_quantum: [3309]u8,
    } {
        // Create classical signature
        const classical_sig = try self.classical_keys.sign(document);
        
        // Create post-quantum signature
        var randomness: [32]u8 = undefined;
        std.crypto.random.bytes(&randomness);
        const pq_sig = try self.pq_keys.sign(document, randomness);
        
        return .{
            .classical = classical_sig,
            .post_quantum = pq_sig,
        };
    }
    
    pub fn verifyDocument(
        classical_public: [32]u8,
        pq_public: [1952]u8,
        document: []const u8,
        signatures: anytype,
    ) !bool {
        // Verify classical signature
        const classical_keypair = zcrypto.asym.ed25519.KeyPair{
            .public_key = classical_public,
            .private_key = undefined, // Not needed for verification
        };
        
        if (!classical_keypair.verify(document, signatures.classical)) {
            return false;
        }
        
        // Verify post-quantum signature
        const pq_valid = try zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair.verify(
            pq_public, document, signatures.post_quantum
        );
        
        return pq_valid;
    }
};
```

### **Example 2: Secure Communication Channel**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub const SecureChannel = struct {
    hybrid_keys: zcrypto.pq.hybrid.X25519_ML_KEM_768.HybridKeyPair,
    shared_secret: ?[64]u8,
    
    pub fn init() !SecureChannel {
        return SecureChannel{
            .hybrid_keys = try zcrypto.pq.hybrid.X25519_ML_KEM_768.HybridKeyPair.generate(),
            .shared_secret = null,
        };
    }
    
    pub fn getPublicKeys(self: *const SecureChannel) struct {
        classical: [32]u8,
        post_quantum: [1184]u8,
    } {
        return .{
            .classical = self.hybrid_keys.classical_public,
            .post_quantum = self.hybrid_keys.pq_public,
        };
    }
    
    pub fn establishSharedSecret(
        self: *SecureChannel,
        peer_classical: [32]u8,
        peer_pq_ciphertext: [1088]u8,
    ) !void {
        self.shared_secret = try self.hybrid_keys.exchange(
            peer_classical, peer_pq_ciphertext
        );
    }
    
    pub fn encryptMessage(
        self: *const SecureChannel,
        allocator: std.mem.Allocator,
        message: []const u8,
    ) !zcrypto.sym.EncryptedData {
        if (self.shared_secret == null) {
            return error.NoSharedSecret;
        }
        
        // Derive symmetric key from shared secret
        const key = self.shared_secret.?[0..16].*;
        const nonce = self.shared_secret.?[16..28].*;
        
        return try zcrypto.sym.encryptAes128Gcm(
            allocator, key, nonce, message, "secure_channel"
        );
    }
    
    pub fn decryptMessage(
        self: *const SecureChannel,
        allocator: std.mem.Allocator,
        encrypted: zcrypto.sym.EncryptedData,
    ) !?[]u8 {
        if (self.shared_secret == null) {
            return error.NoSharedSecret;
        }
        
        const key = self.shared_secret.?[0..16].*;
        const nonce = self.shared_secret.?[16..28].*;
        
        return try zcrypto.sym.decryptAes128Gcm(
            allocator, key, nonce, encrypted.data, encrypted.tag, "secure_channel"
        );
    }
};
```

### **Example 3: QUIC Server Integration**

```zig
const std = @import("std");
const zcrypto = @import("zcrypto");

pub const QuicServer = struct {
    crypto: zcrypto.quic.QuicCrypto,
    connections: std.HashMap(u64, ConnectionState),
    allocator: std.mem.Allocator,
    
    const ConnectionState = struct {
        id: [8]u8,
        keys_derived: bool,
    };
    
    pub fn init(allocator: std.mem.Allocator) QuicServer {
        return QuicServer{
            .crypto = zcrypto.quic.QuicCrypto.init(.TLS_ML_KEM_768_X25519_AES256_GCM_SHA384),
            .connections = std.HashMap(u64, ConnectionState).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn handleNewConnection(self: *QuicServer, connection_id: [8]u8) !void {
        // Derive initial keys for this connection
        try self.crypto.deriveInitialKeys(&connection_id);
        
        const conn_hash = std.hash.Wyhash.hash(0, &connection_id);
        try self.connections.put(conn_hash, ConnectionState{
            .id = connection_id,
            .keys_derived = true,
        });
        
        std.debug.print("New QUIC connection established: {any}\n", .{connection_id});
    }
    
    pub fn processPacket(
        self: *QuicServer,
        connection_id: [8]u8,
        packet: []u8,
        header_len: usize,
        packet_number: u64,
    ) !usize {
        const conn_hash = std.hash.Wyhash.hash(0, &connection_id);
        const connection = self.connections.get(conn_hash) orelse {
            return error.UnknownConnection;
        };
        
        if (!connection.keys_derived) {
            return error.KeysNotDerived;
        }
        
        // Decrypt packet in-place for zero-copy performance
        return try zcrypto.quic.ZeroCopy.decryptInPlace(
            &self.crypto,
            .application,
            true, // server-side
            packet_number,
            packet,
            header_len,
        );
    }
    
    pub fn deinit(self: *QuicServer) void {
        self.connections.deinit();
    }
};
```

---

## ⚠️ **ERROR HANDLING**

### **Error Types**

```zig
/// Core cryptographic errors
pub const CryptoError = error{
    InvalidSeed,
    InvalidPrivateKey,
    InvalidPublicKey,
    InvalidSignature,
    InvalidHmacKey,
    InvalidKeyFormat,
    SignatureVerificationFailed,
    KeyDerivationFailed,
    InsufficientEntropy,
    InvalidKeySize,
    InvalidNonceSize,
    InvalidTagSize,
    DecryptionFailed,
    EncryptionFailed,
    InvalidInput,
};

/// Post-quantum cryptography errors
pub const PQError = error{
    KeyGenFailed,
    EncapsFailed,
    DecapsFailed,
    SigningFailed,
    VerificationFailed,
    InvalidPublicKey,
    InvalidSecretKey,
    InvalidCiphertext,
    InvalidSignature,
    InvalidSharedSecret,
    UnsupportedParameter,
};

/// QUIC cryptography errors
pub const QuicError = error{
    InvalidConnectionId,
    InvalidPacketNumber,
    InvalidKeys,
    PacketDecryptionFailed,
    HeaderProtectionFailed,
    KeyDerivationFailed,
    InvalidCipherSuite,
    EncryptionFailed,
    DecryptionFailed,
    InvalidPacket,
    PQHandshakeFailed,
    HybridModeRequired,
    UnsupportedPQAlgorithm,
};
```

### **Error Handling Patterns**

```zig
// Graceful error handling
fn handleCryptoOperation() !void {
    const keypair = zcrypto.asym.ed25519.generate();
    
    const signature = keypair.sign("message") catch |err| switch (err) {
        error.InvalidInput => {
            std.log.err("Invalid input provided to signing function");
            return;
        },
        error.SignatureVerificationFailed => {
            std.log.err("Failed to create signature");
            return;
        },
        else => return err, // Propagate other errors
    };
    
    // Use signature...
    _ = signature;
}

// Error propagation
fn cryptoWorkflow() ![]u8 {
    const keys = try generateKeys(); // May fail
    const data = try encryptData(keys, "secret"); // May fail
    const hash = zcrypto.hash.sha256(data); // Never fails
    
    return try allocator.dupe(u8, &hash);
}
```

---

## 🔧 **INTEGRATION PATTERNS**

### **For zsig (Digital Signature Service)**

```zig
// zsig integration example
const ZSigService = struct {
    signing_keys: zcrypto.asym.ed25519.KeyPair,
    pq_keys: zcrypto.pq.ml_dsa.ML_DSA_65.KeyPair,
    
    pub fn signData(self: *const ZSigService, data: []const u8) !struct {
        classical: [64]u8,
        quantum_safe: [3309]u8,
        combined_hash: [32]u8,
    } {
        // Create both signatures
        const classical_sig = try self.signing_keys.sign(data);
        
        var randomness: [32]u8 = undefined;
        std.crypto.random.bytes(&randomness);
        const pq_sig = try self.pq_keys.sign(data, randomness);
        
        // Hash both signatures together for integrity
        var hasher = std.crypto.hash.sha3.Sha3_256.init(.{});
        hasher.update(&classical_sig);
        hasher.update(&pq_sig);
        var combined_hash: [32]u8 = undefined;
        hasher.final(&combined_hash);
        
        return .{
            .classical = classical_sig,
            .quantum_safe = pq_sig,
            .combined_hash = combined_hash,
        };
    }
};
```

### **For Network Services**

```zig
// Network service integration
const NetworkCrypto = struct {
    quic_crypto: zcrypto.quic.QuicCrypto,
    tls_config: zcrypto.tls.config.TlsConfig,
    
    pub fn initializeSecureConnection(self: *NetworkCrypto, peer_info: []const u8) !void {
        // Configure for post-quantum security
        self.quic_crypto = zcrypto.quic.QuicCrypto.init(
            .TLS_ML_KEM_768_X25519_AES256_GCM_SHA384
        );
        
        // Derive connection-specific keys
        const connection_id = zcrypto.hash.sha256(peer_info)[0..8].*;
        try self.quic_crypto.deriveInitialKeys(&connection_id);
    }
};
```

### **For Key Management Services**

```zig
// Key management integration
const KeyManager = struct {
    master_key: [32]u8,
    allocator: std.mem.Allocator,
    
    pub fn deriveServiceKey(
        self: *const KeyManager,
        service_name: []const u8,
        key_type: []const u8,
    ) ![]u8 {
        const info = try std.fmt.allocPrint(
            self.allocator, "{s}:{s}", .{ service_name, key_type }
        );
        defer self.allocator.free(info);
        
        return try zcrypto.kdf.deriveKey(
            self.allocator, &self.master_key, info, 32
        );
    }
};
```

---

## 🚀 **PERFORMANCE NOTES**

### **Zero-Copy Operations**

- Use `zcrypto.quic.ZeroCopy` for high-throughput packet processing
- Prefer in-place encryption/decryption when possible
- Stack allocation is preferred over heap allocation for keys

### **Batch Processing**

- Use batch operations for multiple cryptographic operations
- Consider SIMD optimizations available in x86_64 and ARM modules

### **Memory Management**

```zig
// Efficient memory patterns
pub fn efficientCrypto(allocator: std.mem.Allocator) !void {
    // Use stack allocation for keys
    var keypair: zcrypto.asym.ed25519.KeyPair = undefined;
    keypair = zcrypto.asym.ed25519.generate();
    
    // Use arena allocator for temporary operations
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();
    
    // Temporary keys automatically freed
    const derived_key = try zcrypto.kdf.deriveKey(
        arena_allocator, "master", "derived", 32
    );
    _ = derived_key;
    
    // Secure cleanup
    defer zcrypto.util.secureZero(std.mem.asBytes(&keypair));
}
```

---

**🎯 This API documentation provides everything you need to integrate zcrypto v0.5.0 into your projects with confidence and security!**