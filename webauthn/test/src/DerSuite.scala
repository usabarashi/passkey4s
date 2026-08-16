package passkey4s.webauthn

object DerTestVectors {
  def encodeInteger(bytes: Array[Byte]): Array[Byte] = {
    val needsLeadingZero = bytes.nonEmpty && (bytes(0) & 0x80) != 0
    val content = if (needsLeadingZero) Array(0.toByte) ++ bytes else bytes
    Array(0x02.toByte, content.length.toByte) ++ content
  }

  def encodeSignature(r: Array[Byte], s: Array[Byte]): Array[Byte] = {
    val body = encodeInteger(r) ++ encodeInteger(s)
    Array(0x30.toByte, body.length.toByte) ++ body
  }
}

class DerSuite extends munit.FunSuite {
  import DerTestVectors._

  test("round-trips 32-byte components with no sign-bit padding needed") {
    val r = Array.tabulate(32)(i => i.toByte) // starts with 0x00, well under 0x80
    val s = Array.tabulate(32)(i => (i + 1).toByte)
    val raw = Der.toRawEcdsaSignature(encodeSignature(r, s))
    assertEquals(raw.toSeq, (r ++ s).toSeq)
  }

  test("strips the DER sign-bit padding byte when the high bit is set") {
    val r = Array.fill(32)(0xff.toByte) // high bit set -> DER inserts a 0x00 prefix
    val s = Array.fill(32)(0x80.toByte)
    val raw = Der.toRawEcdsaSignature(encodeSignature(r, s))
    assertEquals(raw.toSeq, (r ++ s).toSeq)
  }

  test("left-pads components shorter than 32 bytes (leading zeros stripped by the signer)") {
    val r = Array[Byte](5) // conceptually 0x00...0005
    val s = Array[Byte](1, 2)
    val raw = Der.toRawEcdsaSignature(encodeSignature(r, s))
    val expectedR = Array.fill(31)(0.toByte) :+ 5.toByte
    val expectedS = Array.fill(30)(0.toByte) ++ Array[Byte](1, 2)
    assertEquals(raw.toSeq, (expectedR ++ expectedS).toSeq)
    assertEquals(raw.length, 64)
  }

  test("rejects input that isn't a DER SEQUENCE") {
    intercept[IllegalArgumentException](Der.toRawEcdsaSignature(Array.fill(10)(0.toByte)))
  }
}
