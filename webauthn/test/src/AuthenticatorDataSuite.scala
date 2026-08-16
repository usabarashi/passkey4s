package passkey4s.webauthn

import CborTestVectors._

class AuthenticatorDataSuite extends munit.FunSuite {
  private def be32(n: Long): Array[Byte] =
    Array(((n >> 24) & 0xff).toByte, ((n >> 16) & 0xff).toByte, ((n >> 8) & 0xff).toByte, (n & 0xff).toByte)

  private def coseKey(x: Array[Byte], y: Array[Byte]): Array[Byte] =
    mapHeader(5) ++
      uint(1) ++ uint(2) ++
      uint(3) ++ negint(-7) ++
      negint(-1) ++ uint(1) ++
      negint(-2) ++ bytes(x) ++
      negint(-3) ++ bytes(y)

  test("parses authData without attested credential data (authentication ceremony)") {
    val rpIdHash = Array.fill(32)(7.toByte)
    val flags = 0x01 // user present only
    val signCount = 42L
    val raw = rpIdHash ++ Array(flags.toByte) ++ be32(signCount)

    val parsed = AuthenticatorData.parse(raw)
    assertEquals(parsed.rpIdHash.toSeq, rpIdHash.toSeq)
    assertEquals(parsed.userPresent, true)
    assertEquals(parsed.userVerified, false)
    assertEquals(parsed.signCount, signCount)
    assertEquals(parsed.attestedCredentialData, None)
  }

  test("parses authData with attested credential data (registration ceremony)") {
    val rpIdHash = Array.fill(32)(1.toByte)
    val flags = 0x01 | 0x04 | 0x40 // UP + UV + attested credential data
    val aaguid = Array.fill(16)(2.toByte)
    val credentialId = Array.fill(16)(3.toByte)
    val x = Array.fill(32)(4.toByte)
    val y = Array.fill(32)(5.toByte)

    val raw =
      rpIdHash ++ Array(flags.toByte) ++ be32(0L) ++
        aaguid ++
        Array(0.toByte, credentialId.length.toByte) ++
        credentialId ++
        coseKey(x, y)

    val parsed = AuthenticatorData.parse(raw)
    assertEquals(parsed.userVerified, true)
    val attested = parsed.attestedCredentialData.getOrElse(fail("expected attestedCredentialData"))
    assertEquals(attested.aaguid.toSeq, aaguid.toSeq)
    assertEquals(attested.credentialId.toSeq, credentialId.toSeq)
    assertEquals(attested.publicKey.x.toSeq, x.toSeq)
    assertEquals(attested.publicKey.y.toSeq, y.toSeq)
  }
}
