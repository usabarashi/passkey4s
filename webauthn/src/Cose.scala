package passkey4s.webauthn

/** COSE_Key (RFC 9053) subset: EC2 keys on the P-256 curve, alg ES256 only —
  * matching the scope decided for this sample (single algorithm, no
  * attestation trust chain).
  */
final case class CoseEc2Key(x: Array[Byte], y: Array[Byte])

object Cose {
  private val KtyEc2 = 2L
  private val AlgEs256 = -7L
  private val CrvP256 = 1L

  def parseEc2Key(bytes: Array[Byte], offset: Int = 0): CoseEc2Key = {
    val r = new CborReader(bytes, offset)
    val n = r.readMapHeader()
    var x: Array[Byte] = null
    var y: Array[Byte] = null
    var kty: Long = -1
    var alg: Long = 0
    var crv: Long = -1
    (0 until n).foreach { _ =>
      r.readInt() match {
        case 1 => kty = r.readInt()
        case 3 => alg = r.readInt()
        case -1 => crv = r.readInt()
        case -2 => x = r.readBytes()
        case -3 => y = r.readBytes()
        case _ => r.skipItem()
      }
    }
    require(kty == KtyEc2, s"expected COSE kty=$KtyEc2 (EC2), got $kty")
    require(alg == AlgEs256, s"expected COSE alg=$AlgEs256 (ES256), got $alg")
    require(crv == CrvP256, s"expected COSE crv=$CrvP256 (P-256), got $crv")
    require(x != null && y != null, "COSE_Key missing EC2 x/y coordinate")
    CoseEc2Key(x, y)
  }
}
