import XCTest
import Crypto

class DigestTests: XCTestCase {

    func testMD2() {
        XCTAssertEqual("3b68484d8f4aa7471d4d7a4f3a3650f9", "sam".md2)
    }

    func testMD4() {
        XCTAssertEqual("cd7d17e2d1b18fe34e1a7cc26c1afdf1", "sam".md4)
    }

    func testMD5() {
        XCTAssertEqual("332532dcfaa1cbf61e2a266bd723612c", "sam".md5)
    }

    func testSHA1() {
        XCTAssertEqual("f16bed56189e249fe4ca8ed10a1ecae60e8ceac0", "sam".sha1)
    }

    func testSHA224() {
        XCTAssertEqual("3e158867fde8c88755ad7d28ac2525c612df7957efb527783ca41328", "sam".sha224)
    }

    func testSHA256() {
        XCTAssertEqual("e96e02d8e47f2a7c03be5117b3ed175c52aa30fb22028cf9c96f261563577605", "sam".sha256)
    }

    func testSHA384() {
        XCTAssertEqual("f43211f34235f416ed799126e46ff3b77155acff484eec2bbe93e081082a30e3dd7462217470747fdc8bc4fb9facf205", "sam".sha384)
    }

    func testSHA512() {
        XCTAssertEqual("aa9a88785afb81fcb66da5b86d0aaf543dd883c8cf1e74f2f42c62195006606c69613170d56d2ecb8db6fb03f5acb6bdd0ffaf54bdf788854ddafc6becfdf3c7", "sam".sha512)
    }
    
}

class HMACTests: XCTestCase {

    let key = "secret"
    let message = "sam"

    func testSHA1() {
        let signature = HMAC.sign(message: message, algorithm: .sha1, key: key)
        XCTAssertEqual("1a90fa4e73686dfca75f5411d9fb81951edf1292", signature)
    }

    func testMD5() {
        let signature = HMAC.sign(message: message, algorithm: .md5, key: key)
        XCTAssertEqual("0266f2e4980a1540f128da1d32166391", signature)
    }

    func testSHA256() {
        let signature = HMAC.sign(message: message, algorithm: .sha256, key: key)
        XCTAssertEqual("6d2f3199a75036d1bd819961a149641ebe540aae0b10bbb821f0cb98039b1a7b", signature)
    }

    func testSHA384() {
        let signature = HMAC.sign(message: message, algorithm: .sha384, key: key)
        XCTAssertEqual("2fad06c8d32e66d33c3b24e290e37f59cd4470207d7749cbabbe8ea7d751077badc1e6d18b863b968c81ff92cbeccecd", signature)
    }

    func testSHA512() {
        let signature = HMAC.sign(message: message, algorithm: .sha512, key: key)
        XCTAssertEqual("4b49d3f9dfa51eaf638b85c2887875144ad5dafeacefdcc72bd73f19f2ae2a7ae182ee2e3f6684b7f042d8d122c4558b64be8b072ce9a69a1ceb96aa688cadfd", signature)
    }

    func testSHA224() {
        let signature = HMAC.sign(message: message, algorithm: .sha224, key: key)
        XCTAssertEqual("e9c2dc5a9fbd278db52e37a7cbfb9f2897774287daaa0bb33a4f98f5", signature)
    }
}
