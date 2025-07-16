//! By convention, root.zig is the root source file when making a library.
//! This file exports the zsig module for use as a library dependency.

const zsig = @import("zsig.zig");

// Re-export everything from zsig module
pub const version = zsig.version;
pub const info = zsig.info;
pub const backend = zsig.backend;
pub const key = zsig.key;
pub const sign = zsig.sign;
pub const verify = zsig.verify;
pub const Keypair = zsig.Keypair;
pub const Signature = zsig.Signature;
pub const VerificationResult = zsig.VerificationResult;
pub const PUBLIC_KEY_SIZE = zsig.PUBLIC_KEY_SIZE;
pub const PRIVATE_KEY_SIZE = zsig.PRIVATE_KEY_SIZE;
pub const SIGNATURE_SIZE = zsig.SIGNATURE_SIZE;
pub const SEED_SIZE = zsig.SEED_SIZE;
pub const generateKeypair = zsig.generateKeypair;
pub const keypairFromSeed = zsig.keypairFromSeed;
pub const keypairFromPassphrase = zsig.keypairFromPassphrase;
pub const signMessage = zsig.signMessage;
pub const signBytes = zsig.signBytes;
pub const signInline = zsig.signInline;
pub const signWithContext = zsig.signWithContext;
pub const signBatch = zsig.signBatch;
pub const signChallenge = zsig.signChallenge;
pub const verifySignature = zsig.verifySignature;
pub const verifyInline = zsig.verifyInline;
pub const verifyWithContext = zsig.verifyWithContext;
pub const verifyBatch = zsig.verifyBatch;
pub const verifyChallenge = zsig.verifyChallenge;
pub const verifyDetailed = zsig.verifyDetailed;
pub const KeyDerivation = zsig.KeyDerivation;
pub const advancedPrint = zsig.advancedPrint;

// Include tests from zsig module
test {
    @import("std").testing.refAllDecls(@This());
}
