package passkey4s.webauthn

/** Minimal CBOR (RFC 8949) reader covering only what WebAuthn's
  * attestationObject / COSE_Key structures need: unsigned/negative integers,
  * byte strings, text strings, arrays, and maps. Deliberately not a general
  * purpose CBOR library.
  */
final class CborReader(bytes: Array[Byte], initialPos: Int = 0) {
  private var pos: Int = initialPos

  def position: Int = pos

  private def u8(): Int = {
    val b = bytes(pos) & 0xff
    pos += 1
    b
  }

  private def peekMajorType(): Int = (bytes(pos) & 0xff) >> 5

  private def readHead(): (Int, Long) = {
    val first = u8()
    val majorType = first >> 5
    val info = first & 0x1f
    val arg: Long =
      if (info < 24) info.toLong
      else if (info == 24) u8().toLong
      else if (info == 25) (0 until 2).foldLeft(0L)((v, _) => (v << 8) | u8())
      else if (info == 26) (0 until 4).foldLeft(0L)((v, _) => (v << 8) | u8())
      else if (info == 27) (0 until 8).foldLeft(0L)((v, _) => (v << 8) | u8())
      else throw new IllegalArgumentException(s"unsupported CBOR additional info $info")
    (majorType, arg)
  }

  def readInt(): Long = {
    val (majorType, arg) = readHead()
    majorType match {
      case 0 => arg
      case 1 => -1L - arg
      case other => throw new IllegalArgumentException(s"expected CBOR integer, got major type $other")
    }
  }

  def readBytes(): Array[Byte] = {
    val (majorType, len) = readHead()
    if (majorType != 2)
      throw new IllegalArgumentException(s"expected CBOR byte string, got major type $majorType")
    val n = len.toInt
    val out = bytes.slice(pos, pos + n)
    pos += n
    out
  }

  def readText(): String = {
    val (majorType, len) = readHead()
    if (majorType != 3)
      throw new IllegalArgumentException(s"expected CBOR text string, got major type $majorType")
    val n = len.toInt
    val s = new String(bytes, pos, n, "UTF-8")
    pos += n
    s
  }

  /** Consumes the map header, returning the number of key/value pairs. */
  def readMapHeader(): Int = {
    val (majorType, len) = readHead()
    if (majorType != 5)
      throw new IllegalArgumentException(s"expected CBOR map, got major type $majorType")
    len.toInt
  }

  /** Skips exactly one CBOR data item, regardless of its type. */
  def skipItem(): Unit =
    peekMajorType() match {
      case 0 | 1 => readInt(): Unit
      case 2 => readBytes(): Unit
      case 3 => readText(): Unit
      case 4 =>
        val (_, len) = readHead()
        (0L until len).foreach(_ => skipItem())
      case 5 =>
        val (_, len) = readHead()
        (0L until len).foreach(_ => { skipItem(); skipItem() })
      case other => throw new IllegalArgumentException(s"cannot skip CBOR major type $other")
    }
}
