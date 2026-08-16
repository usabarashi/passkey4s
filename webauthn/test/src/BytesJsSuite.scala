package passkey4s.webauthn

class BytesJsSuite extends munit.FunSuite {
  test("round-trips through Uint8Array and ArrayBuffer") {
    val bytes: Array[Byte] = Array(0, 1, -1, 127, -128, 42)
    assertEquals(BytesJs.fromUint8Array(BytesJs.toUint8Array(bytes)).toSeq, bytes.toSeq)
    assertEquals(BytesJs.fromArrayBuffer(BytesJs.toArrayBuffer(bytes)).toSeq, bytes.toSeq)
  }
}
