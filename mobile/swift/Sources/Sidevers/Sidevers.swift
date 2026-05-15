//
//  Sidevers.swift — idiomatic Swift wrappers around the C ABI in `sidevers.h`.
//
//  Memory ownership: every Rust-allocated buffer or C string is freed via
//  the matching sv_free_* call inside the wrappers below. Callers see Swift
//  values (Data, String) and never touch raw pointers.
//
//  Error handling: the FFI's `SvStatus` codes are converted into thrown
//  `SideversError` values. The last-error message (when set by the FFI) is
//  attached.

import Foundation
import SideversFFI

/// Errors thrown by the Sidevers SDK.
public enum SideversError: Error, CustomStringConvertible {
    case nullPointer
    case invalidInput(String)
    case crypto(String)
    case decode(String)
    case csprngUnavailable(String)
    case `internal`(String)

    public var description: String {
        switch self {
        case .nullPointer:                return "Sidevers: null pointer"
        case .invalidInput(let m):        return "Sidevers: invalid input — \(m)"
        case .crypto(let m):              return "Sidevers: crypto — \(m)"
        case .decode(let m):              return "Sidevers: decode — \(m)"
        case .csprngUnavailable(let m):   return "Sidevers: CSPRNG unavailable — \(m)"
        case .internal(let m):            return "Sidevers: internal — \(m)"
        }
    }
}

/// What kind of entity an address points at.
public enum AddressKind {
    case side
    case verse

    fileprivate var cValue: SvAddressKind {
        switch self {
        case .side:  return SvAddressKind_Side
        case .verse: return SvAddressKind_Verse
        }
    }

    fileprivate static func from(_ c: SvAddressKind) -> AddressKind {
        switch c {
        case SvAddressKind_Verse: return .verse
        default:                  return .side
        }
    }
}

/// A parsed Sidevers address: 32-byte Ed25519 public key + kind tag.
public struct Address: Hashable {
    public let pubkey: Data         // exactly 32 bytes
    public let kind: AddressKind

    /// Encode this address as a bech32m string.
    public func encoded() throws -> String {
        precondition(pubkey.count == 32, "Sidevers Address pubkey must be 32 bytes")
        let cstr = pubkey.withUnsafeBytes { raw -> UnsafeMutablePointer<CChar>? in
            let p = raw.bindMemory(to: UInt8.self).baseAddress!
            return sv_address_encode(p, kind.cValue)
        }
        guard let cstr else { throw lastError() ?? .internal("address encode returned null") }
        defer { sv_free_string(cstr) }
        return String(cString: cstr)
    }

    /// Parse a bech32m-encoded address.
    public static func parse(_ s: String) throws -> Address {
        var pubkey = Data(count: 32)
        var kind: SvAddressKind = SvAddressKind_Side
        let status = pubkey.withUnsafeMutableBytes { raw -> SvStatus in
            let p = raw.bindMemory(to: UInt8.self).baseAddress!
            return s.withCString { addr in
                sv_address_decode(addr, p, &kind)
            }
        }
        try Sidevers.check(status)
        return Address(pubkey: pubkey, kind: AddressKind.from(kind))
    }
}

/// The entry point. Stateless — all methods are static.
public enum Sidevers {

    /// Generate a fresh master seed from the OS CSPRNG. Returns 32 bytes.
    public static func generateMaster() throws -> Data {
        var seed = Data(count: 32)
        let status = seed.withUnsafeMutableBytes { raw -> SvStatus in
            let p = raw.bindMemory(to: UInt8.self).baseAddress!
            return sv_keygen_master(p)
        }
        try check(status)
        return seed
    }

    /// Derive a side seed from a master seed under the given label.
    public static func deriveSide(master: Data, label: String) throws -> Data {
        precondition(master.count == 32, "master must be 32 bytes")
        var sideSeed = Data(count: 32)
        let status = master.withUnsafeBytes { masterRaw -> SvStatus in
            let m = masterRaw.bindMemory(to: UInt8.self).baseAddress!
            return sideSeed.withUnsafeMutableBytes { sideRaw -> SvStatus in
                let s = sideRaw.bindMemory(to: UInt8.self).baseAddress!
                return label.withCString { l in
                    sv_derive_side(m, l, s)
                }
            }
        }
        try check(status)
        return sideSeed
    }

    /// Compute the 32-byte Ed25519 public key for any seed (master, side,
    /// or verse — they all share the same keyspace).
    public static func pubkey(from seed: Data) throws -> Data {
        precondition(seed.count == 32, "seed must be 32 bytes")
        var pk = Data(count: 32)
        let status = seed.withUnsafeBytes { seedRaw -> SvStatus in
            let s = seedRaw.bindMemory(to: UInt8.self).baseAddress!
            return pk.withUnsafeMutableBytes { pkRaw -> SvStatus in
                let p = pkRaw.bindMemory(to: UInt8.self).baseAddress!
                return sv_pubkey_from_seed(s, p)
            }
        }
        try check(status)
        return pk
    }

    /// Build a signed, encrypted DirectMessage envelope ready for the wire.
    public static func sealDirectMessage(
        senderSeed: Data,
        recipientPubkey: Data,
        text: String
    ) throws -> Data {
        precondition(senderSeed.count == 32)
        precondition(recipientPubkey.count == 32)
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: Int = 0
        let status = senderSeed.withUnsafeBytes { sRaw -> SvStatus in
            let s = sRaw.bindMemory(to: UInt8.self).baseAddress!
            return recipientPubkey.withUnsafeBytes { rRaw -> SvStatus in
                let r = rRaw.bindMemory(to: UInt8.self).baseAddress!
                let textData = Array(text.utf8)
                return textData.withUnsafeBufferPointer { tBuf -> SvStatus in
                    let t = tBuf.baseAddress!
                    return sv_dm_seal_text(s, r, t, textData.count, &outPtr, &outLen)
                }
            }
        }
        try check(status)
        defer {
            if let outPtr { sv_free_buffer(outPtr, outLen) }
        }
        guard let outPtr else { throw SideversError.internal("seal returned null buffer") }
        return Data(bytes: outPtr, count: outLen)
    }

    /// Verify, decrypt, and extract the body of a DirectMessage envelope
    /// addressed to this side. Returns `(senderPubkey, plaintext)`.
    public static func openDirectMessage(
        recipientSeed: Data,
        wire: Data
    ) throws -> (sender: Data, text: String) {
        precondition(recipientSeed.count == 32)
        var sender = Data(count: 32)
        var textPtr: UnsafeMutablePointer<UInt8>? = nil
        var textLen: Int = 0
        let status = recipientSeed.withUnsafeBytes { recvRaw -> SvStatus in
            let recv = recvRaw.bindMemory(to: UInt8.self).baseAddress!
            return wire.withUnsafeBytes { wireRaw -> SvStatus in
                let w = wireRaw.bindMemory(to: UInt8.self).baseAddress!
                return sender.withUnsafeMutableBytes { senderRaw -> SvStatus in
                    let senderPtr = senderRaw.bindMemory(to: UInt8.self).baseAddress!
                    return sv_dm_open_text(recv, w, wire.count, senderPtr, &textPtr, &textLen)
                }
            }
        }
        try check(status)
        defer {
            if let textPtr { sv_free_buffer(textPtr, textLen) }
        }
        guard let textPtr else { throw SideversError.internal("open returned null buffer") }
        let plain = Data(bytes: textPtr, count: textLen)
        guard let text = String(data: plain, encoding: .utf8) else {
            throw SideversError.decode("DM plaintext was not valid UTF-8")
        }
        return (sender, text)
    }

    /// Sign a fresh linkage proof binding two sides the caller owns.
    public static func signLinkage(sideA: Data, sideB: Data, issuedAt: UInt64) throws -> Data {
        precondition(sideA.count == 32 && sideB.count == 32)
        var outPtr: UnsafeMutablePointer<UInt8>? = nil
        var outLen: Int = 0
        let status = sideA.withUnsafeBytes { aRaw -> SvStatus in
            let a = aRaw.bindMemory(to: UInt8.self).baseAddress!
            return sideB.withUnsafeBytes { bRaw -> SvStatus in
                let b = bRaw.bindMemory(to: UInt8.self).baseAddress!
                return sv_linkage_sign(a, b, issuedAt, &outPtr, &outLen)
            }
        }
        try check(status)
        defer {
            if let outPtr { sv_free_buffer(outPtr, outLen) }
        }
        guard let outPtr else { throw SideversError.internal("linkage sign returned null") }
        return Data(bytes: outPtr, count: outLen)
    }

    /// Verify a linkage proof. Returns the two side public keys and the
    /// `issued_at` timestamp the proof was signed at.
    public static func verifyLinkage(wire: Data) throws -> (sideA: Data, sideB: Data, issuedAt: UInt64) {
        var sideA = Data(count: 32)
        var sideB = Data(count: 32)
        var issuedAt: UInt64 = 0
        let status = wire.withUnsafeBytes { wireRaw -> SvStatus in
            let w = wireRaw.bindMemory(to: UInt8.self).baseAddress!
            return sideA.withUnsafeMutableBytes { aRaw -> SvStatus in
                let a = aRaw.bindMemory(to: UInt8.self).baseAddress!
                return sideB.withUnsafeMutableBytes { bRaw -> SvStatus in
                    let b = bRaw.bindMemory(to: UInt8.self).baseAddress!
                    return sv_linkage_verify(w, wire.count, a, b, &issuedAt)
                }
            }
        }
        try check(status)
        return (sideA, sideB, issuedAt)
    }

    // ---------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------

    fileprivate static func check(_ status: SvStatus) throws {
        if status == SvStatus_Ok { return }
        let msg = lastErrorMessage() ?? "unknown error"
        switch status {
        case SvStatus_NullPtr:          throw SideversError.nullPointer
        case SvStatus_InvalidInput:     throw SideversError.invalidInput(msg)
        case SvStatus_Crypto:           throw SideversError.crypto(msg)
        case SvStatus_Decode:           throw SideversError.decode(msg)
        case SvStatus_CsprngUnavailable: throw SideversError.csprngUnavailable(msg)
        default:                        throw SideversError.internal(msg)
        }
    }

    fileprivate static func lastErrorMessage() -> String? {
        guard let cstr = sv_last_error_message() else { return nil }
        defer { sv_free_string(cstr) }
        return String(cString: cstr)
    }
}

fileprivate func lastError() -> SideversError? {
    guard let msg = Sidevers.lastErrorMessage() else { return nil }
    return .internal(msg)
}
