package passkey4s.webauthn

import scala.concurrent.{ExecutionContext, Future}
import scala.scalajs.js
import scala.scalajs.js.Thenable.Implicits._
import scala.scalajs.js.typedarray.Uint8Array

/** ES256 (ECDSA P-256 / SHA-256) signature verification only — the sole
  * algorithm this sample supports, per the scoped-down verification plan.
  */
object Es256 {
  private def importAlgorithm =
    js.Dynamic.literal(name = "ECDSA", namedCurve = "P-256")

  private def verifyAlgorithm =
    js.Dynamic.literal(name = "ECDSA", hash = "SHA-256")

  private def toUint8Array(bytes: Array[Byte]): Uint8Array = {
    val arr = new Uint8Array(bytes.length)
    var i = 0
    while (i < bytes.length) {
      arr(i) = (bytes(i) & 0xff).toShort
      i += 1
    }
    arr
  }

  def verify(publicKey: CoseEc2Key, rawSignature: Array[Byte], signedData: Array[Byte])(implicit
      ec: ExecutionContext
  ): Future[Boolean] = {
    val jwk = js.Dynamic.literal(
      kty = "EC",
      crv = "P-256",
      x = Base64Url.encode(publicKey.x),
      y = Base64Url.encode(publicKey.y),
      ext = true
    )
    for {
      key <- WebCrypto.subtle.importKey("jwk", jwk, importAlgorithm, false, js.Array("verify"))
      valid <- WebCrypto.subtle.verify(verifyAlgorithm, key, toUint8Array(rawSignature), toUint8Array(signedData))
    } yield valid
  }
}
