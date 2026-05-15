//
//  SideversTests.swift — smoke tests for the Swift wrapper.
//
//  These are exactly the operations a real iOS app's "first launch" flow
//  would perform: generate identity, derive a side, encode its address,
//  exchange a DM with another party.

import XCTest
@testable import Sidevers

final class SideversTests: XCTestCase {

    func testKeygenAndAddress() throws {
        let master = try Sidevers.generateMaster()
        XCTAssertEqual(master.count, 32)
        // Astronomically unlikely the CSPRNG returns all-zeros.
        XCTAssertTrue(master.contains { $0 != 0 })

        let side = try Sidevers.deriveSide(master: master, label: "work")
        XCTAssertEqual(side.count, 32)

        let pubkey = try Sidevers.pubkey(from: side)
        XCTAssertEqual(pubkey.count, 32)

        let addr = Address(pubkey: pubkey, kind: .side)
        let encoded = try addr.encoded()
        XCTAssertTrue(encoded.hasPrefix("sv1"))

        let parsed = try Address.parse(encoded)
        XCTAssertEqual(parsed, addr)
    }

    func testDMRoundTrip() throws {
        let aliceMaster = try Sidevers.generateMaster()
        let bobMaster = try Sidevers.generateMaster()
        let aliceSide = try Sidevers.deriveSide(master: aliceMaster, label: "work")
        let bobSide = try Sidevers.deriveSide(master: bobMaster, label: "close")
        let bobPubkey = try Sidevers.pubkey(from: bobSide)

        let wire = try Sidevers.sealDirectMessage(
            senderSeed: aliceSide,
            recipientPubkey: bobPubkey,
            text: "hello from Swift"
        )
        XCTAssertGreaterThan(wire.count, 100) // envelope is non-trivial

        let (sender, plaintext) = try Sidevers.openDirectMessage(
            recipientSeed: bobSide,
            wire: wire
        )
        let expectedAliceP = try Sidevers.pubkey(from: aliceSide)
        XCTAssertEqual(sender, expectedAliceP)
        XCTAssertEqual(plaintext, "hello from Swift")
    }

    func testLinkageRoundTrip() throws {
        let master = try Sidevers.generateMaster()
        let sideA = try Sidevers.deriveSide(master: master, label: "public")
        let sideB = try Sidevers.deriveSide(master: master, label: "private")

        let proof = try Sidevers.signLinkage(sideA: sideA, sideB: sideB, issuedAt: 1_700_000_000)
        let (pa, pb, ts) = try Sidevers.verifyLinkage(wire: proof)

        let expectedA = try Sidevers.pubkey(from: sideA)
        let expectedB = try Sidevers.pubkey(from: sideB)
        XCTAssertEqual(pa, expectedA)
        XCTAssertEqual(pb, expectedB)
        XCTAssertEqual(ts, 1_700_000_000)
    }

    func testInvalidAddressThrows() {
        XCTAssertThrowsError(try Address.parse("sv1ABCdef"))
    }
}
