package passkey4s.webauthn

/** WebAuthn signatures are ASN.1 DER-encoded ECDSA (SEQUENCE of two
  * INTEGERs), but WebCrypto's `verify("ECDSA", ...)` expects the raw
  * IEEE P1363 r||s encoding. This is the #1 bug in hand-rolled relying
  * party implementations, so it gets its own file and its own tests.
  */
object Der {
  def toRawEcdsaSignature(der: Array[Byte], componentSize: Int = 32): Array[Byte] = {
    require(der.length >= 8 && (der(0) & 0xff) == 0x30, "not a DER SEQUENCE")

    val lengthByte = der(1) & 0xff
    var pos = if ((lengthByte & 0x80) != 0) 2 + (lengthByte & 0x7f) else 2

    def readInteger(): Array[Byte] = {
      require((der(pos) & 0xff) == 0x02, s"expected DER INTEGER tag at offset $pos")
      pos += 1
      val len = der(pos) & 0xff
      pos += 1
      val value = der.slice(pos, pos + len)
      pos += len
      value
    }

    def toFixedWidth(component: Array[Byte]): Array[Byte] = {
      val trimmed = component.dropWhile(_ == 0)
      require(trimmed.length <= componentSize, s"integer does not fit in $componentSize bytes")
      val out = new Array[Byte](componentSize)
      Array.copy(trimmed, 0, out, componentSize - trimmed.length, trimmed.length)
      out
    }

    val r = readInteger()
    val s = readInteger()
    toFixedWidth(r) ++ toFixedWidth(s)
  }
}
