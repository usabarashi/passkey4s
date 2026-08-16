package passkey4s.webauthn

class SecureRandomSuite extends munit.FunSuite {
  test("produces the requested number of bytes and varies between calls") {
    val a = SecureRandom.bytes(32)
    val b = SecureRandom.bytes(32)
    assertEquals(a.length, 32)
    assertEquals(b.length, 32)
    assert(!a.sameElements(b), "two independent random draws collided")
  }

  test("base64UrlToken produces a non-empty unpadded token") {
    val token = SecureRandom.base64UrlToken()
    assert(token.nonEmpty)
    assert(!token.contains('='))
  }
}
