package passkey4s.webauthn

import CborTestVectors._

class CoseSuite extends munit.FunSuite {
  private def ec2Key(x: Array[Byte], y: Array[Byte], kty: Long = 2, alg: Long = -7, crv: Long = 1): Array[Byte] = {
    def keyBytes(k: Long): Array[Byte] = if (k < 0) negint(k) else uint(k)
    mapHeader(5) ++
      uint(1) ++ keyBytes(kty) ++
      uint(3) ++ keyBytes(alg) ++
      negint(-1) ++ keyBytes(crv) ++
      negint(-2) ++ bytes(x) ++
      negint(-3) ++ bytes(y)
  }

  test("parses a well-formed EC2/ES256/P-256 key") {
    val x = Array.tabulate(32)(i => i.toByte)
    val y = Array.tabulate(32)(i => (i + 100).toByte)
    val key = Cose.parseEc2Key(ec2Key(x, y))
    assertEquals(key.x.toSeq, x.toSeq)
    assertEquals(key.y.toSeq, y.toSeq)
  }

  test("parses regardless of key ordering") {
    val x = Array.fill(32)(1.toByte)
    val y = Array.fill(32)(2.toByte)
    // -2/-3 (x/y) listed before 1/3/-1 (kty/alg/crv)
    val reordered =
      mapHeader(5) ++
        negint(-2) ++ bytes(x) ++
        negint(-3) ++ bytes(y) ++
        uint(1) ++ uint(2) ++
        uint(3) ++ negint(-7) ++
        negint(-1) ++ uint(1)
    val key = Cose.parseEc2Key(reordered)
    assertEquals(key.x.toSeq, x.toSeq)
    assertEquals(key.y.toSeq, y.toSeq)
  }

  test("rejects a non-EC2 kty") {
    val x = Array.fill(32)(1.toByte)
    val y = Array.fill(32)(2.toByte)
    intercept[IllegalArgumentException](Cose.parseEc2Key(ec2Key(x, y, kty = 1)))
  }

  test("rejects a non-ES256 algorithm") {
    val x = Array.fill(32)(1.toByte)
    val y = Array.fill(32)(2.toByte)
    intercept[IllegalArgumentException](Cose.parseEc2Key(ec2Key(x, y, alg = -257)))
  }
}
