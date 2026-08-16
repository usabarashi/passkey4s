package passkey4s.webauthn

import CborTestVectors._

class RegistrationSuite extends munit.FunSuite {
  private def be32(n: Long): Array[Byte] =
    Array(((n >> 24) & 0xff).toByte, ((n >> 16) & 0xff).toByte, ((n >> 8) & 0xff).toByte, (n & 0xff).toByte)

  private def coseKey(x: Array[Byte], y: Array[Byte]): Array[Byte] =
    mapHeader(5) ++
      uint(1) ++ uint(2) ++
      uint(3) ++ negint(-7) ++
      negint(-1) ++ uint(1) ++
      negint(-2) ++ bytes(x) ++
      negint(-3) ++ bytes(y)

  private val rpIdHash = Array.fill(32)(0x11.toByte)
  private val credentialId = Array.fill(16)(0x22.toByte)
  private val publicKeyX = Array.fill(32)(0x33.toByte)
  private val publicKeyY = Array.fill(32)(0x44.toByte)
  private val challenge = "abc123-challenge"
  private val origin = "https://passkey4s.example.workers.dev"

  private def authData(flags: Int, signCount: Long = 0L): Array[Byte] =
    rpIdHash ++ Array(flags.toByte) ++ be32(signCount) ++
      Array.fill(16)(0xaa.toByte) ++
      Array(0.toByte, credentialId.length.toByte) ++
      credentialId ++
      coseKey(publicKeyX, publicKeyY)

  private def attestationObject(flags: Int = 0x01 | 0x04 | 0x40): Array[Byte] =
    mapHeader(3) ++
      text("fmt") ++ text("none") ++
      text("attStmt") ++ mapHeader(0) ++
      text("authData") ++ bytes(authData(flags))

  private def clientDataJSON(`type`: String = "webauthn.create", chal: String = challenge, org: String = origin): Array[Byte] =
    s"""{"type":"${`type`}","challenge":"$chal","origin":"$org"}""".getBytes("UTF-8")

  test("accepts a well-formed registration ceremony") {
    val result = Registration.verify(clientDataJSON(), attestationObject(), challenge, origin, rpIdHash)
    result match {
      case Right(cred) =>
        assertEquals(cred.credentialId.toSeq, credentialId.toSeq)
        assertEquals(cred.publicKey.x.toSeq, publicKeyX.toSeq)
        assertEquals(cred.publicKey.y.toSeq, publicKeyY.toSeq)
      case Left(reason) => fail(s"expected success, got: $reason")
    }
  }

  test("rejects a challenge mismatch") {
    val result = Registration.verify(clientDataJSON(chal = "wrong"), attestationObject(), challenge, origin, rpIdHash)
    assertEquals(result, Left("challenge mismatch"))
  }

  test("rejects an origin mismatch") {
    val result = Registration.verify(clientDataJSON(org = "https://evil.example"), attestationObject(), challenge, origin, rpIdHash)
    assertEquals(result, Left("origin mismatch"))
  }

  test("rejects the wrong clientData type") {
    val result = Registration.verify(clientDataJSON(`type` = "webauthn.get"), attestationObject(), challenge, origin, rpIdHash)
    assertEquals(result, Left("unexpected clientData.type: webauthn.get"))
  }

  test("rejects an rpIdHash mismatch") {
    val wrongRpIdHash = Array.fill(32)(0xff.toByte)
    val result = Registration.verify(clientDataJSON(), attestationObject(), challenge, origin, wrongRpIdHash)
    assertEquals(result, Left("rpIdHash mismatch"))
  }

  test("rejects a missing user-verified flag") {
    val result = Registration.verify(clientDataJSON(), attestationObject(flags = 0x01 | 0x40), challenge, origin, rpIdHash)
    assertEquals(result, Left("user not verified"))
  }
}
