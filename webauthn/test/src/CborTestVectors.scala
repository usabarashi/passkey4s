package passkey4s.webauthn

/** Small hand-written CBOR *encoder*, used only to build test vectors for
  * the production *decoder*. Deliberately kept separate/dumber than
  * CborReader so a shared bug wouldn't hide behind both sides agreeing.
  */
object CborTestVectors {
  def uint(n: Long): Array[Byte] = head(0, n)

  def negint(n: Long): Array[Byte] = {
    require(n < 0, "negint requires a negative value")
    head(1, -1L - n)
  }

  def bytes(b: Array[Byte]): Array[Byte] = head(2, b.length.toLong) ++ b

  def text(s: String): Array[Byte] = {
    val utf8 = s.getBytes("UTF-8")
    head(3, utf8.length.toLong) ++ utf8
  }

  def mapHeader(pairCount: Int): Array[Byte] = head(5, pairCount.toLong)

  private def head(majorType: Int, arg: Long): Array[Byte] = {
    val first = majorType << 5
    if (arg < 24) Array((first | arg).toByte)
    else if (arg < 256) Array((first | 24).toByte, arg.toByte)
    else if (arg < 65536)
      Array((first | 25).toByte, ((arg >> 8) & 0xff).toByte, (arg & 0xff).toByte)
    else
      Array(
        (first | 26).toByte,
        ((arg >> 24) & 0xff).toByte,
        ((arg >> 16) & 0xff).toByte,
        ((arg >> 8) & 0xff).toByte,
        (arg & 0xff).toByte
      )
  }
}
