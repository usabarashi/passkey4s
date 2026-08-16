package passkey4s.webauthn

import scala.concurrent.ExecutionContext.Implicits.global
import scala.scalajs.js
import scala.scalajs.js.Thenable.Implicits._
import scala.scalajs.js.typedarray.{ArrayBuffer, Uint8Array}

// Node 19+ exposes globalThis.crypto, so this integration test can run
// under the same `mill webauthn.test` as the pure-function suites.
@js.native
trait SubtleCryptoTestExtras extends js.Object {
  def generateKey(algorithm: js.Any, extractable: Boolean, keyUsages: js.Array[String]): js.Promise[js.Dynamic] =
    js.native
  def sign(algorithm: js.Any, key: CryptoKey, data: Uint8Array): js.Promise[ArrayBuffer] = js.native
  def exportKey(format: String, key: CryptoKey): js.Promise[js.Dynamic] = js.native
}

class Es256Suite extends munit.FunSuite {
  private def extras: SubtleCryptoTestExtras = WebCrypto.subtle.asInstanceOf[SubtleCryptoTestExtras]

  private def toBytes(buf: ArrayBuffer): Array[Byte] = {
    val view = new Uint8Array(buf)
    Array.tabulate(view.length)(i => view(i).toByte)
  }

  private def toUint8(bytes: Array[Byte]): Uint8Array = {
    val arr = new Uint8Array(bytes.length)
    var i = 0
    while (i < bytes.length) {
      arr(i) = (bytes(i) & 0xff).toShort
      i += 1
    }
    arr
  }

  test("verifies a signature produced by a freshly generated P-256 key, rejects a tampered one") {
    val data = toUint8("hello passkey4s".getBytes("UTF-8"))
    val genAlgorithm = js.Dynamic.literal(name = "ECDSA", namedCurve = "P-256")
    val signAlgorithm = js.Dynamic.literal(name = "ECDSA", hash = "SHA-256")

    for {
      keyPair <- extras.generateKey(genAlgorithm, true, js.Array("sign", "verify"))
      publicJwk <- extras.exportKey("jwk", keyPair.publicKey.asInstanceOf[CryptoKey])
      signatureBuf <- extras.sign(signAlgorithm, keyPair.privateKey.asInstanceOf[CryptoKey], data)
      publicKey = CoseEc2Key(
        x = Base64Url.decode(publicJwk.x.asInstanceOf[String]),
        y = Base64Url.decode(publicJwk.y.asInstanceOf[String])
      )
      signature = toBytes(signatureBuf)
      valid <- Es256.verify(publicKey, signature, "hello passkey4s".getBytes("UTF-8"))
      invalidData <- Es256.verify(publicKey, signature, "tampered!!!!!!!".getBytes("UTF-8"))
    } yield {
      assert(valid, "expected a genuine signature to verify")
      assert(!invalidData, "expected a signature over different data to fail verification")
    }
  }
}
