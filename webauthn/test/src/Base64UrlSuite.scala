package passkey4s.webauthn

class Base64UrlSuite extends munit.FunSuite {
  test("round-trips arbitrary bytes") {
    val bytes: Array[Byte] = Array(0, 1, 2, 3, -2, -1, 127, -128, 10, 13)
    assertEquals(Base64Url.decode(Base64Url.encode(bytes)).toSeq, bytes.toSeq)
  }

  test("encode has no padding or +/ characters") {
    val encoded = Base64Url.encode(Array[Byte](1, 2, 3, 4, 5))
    assert(!encoded.contains('='))
    assert(!encoded.contains('+'))
    assert(!encoded.contains('/'))
  }

  test("decode handles unpadded input of every length mod 4") {
    for (n <- 1 to 8) {
      val bytes = Array.tabulate(n)(i => i.toByte)
      assertEquals(Base64Url.decode(Base64Url.encode(bytes)).toSeq, bytes.toSeq)
    }
  }
}
