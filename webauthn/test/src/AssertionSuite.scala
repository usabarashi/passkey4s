package passkey4s.webauthn

import scala.concurrent.ExecutionContext.Implicits.global
import scala.scalajs.js
import scala.scalajs.js.Thenable.Implicits._
import scala.scalajs.js.typedarray.{ArrayBuffer, Uint8Array}

class AssertionSuite extends munit.FunSuite {
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

  private val rpIdHash = Array.fill(32)(0x55.toByte)
  private val challenge = "login-challenge-xyz"
  private val origin = "https://passkey4s.example.workers.dev"

  private def authenticatorData(flags: Int, signCount: Long): Array[Byte] = {
    def be32(n: Long): Array[Byte] =
      Array(((n >> 24) & 0xff).toByte, ((n >> 16) & 0xff).toByte, ((n >> 8) & 0xff).toByte, (n & 0xff).toByte)
    rpIdHash ++ Array(flags.toByte) ++ be32(signCount)
  }

  private def clientDataJSON(chal: String = challenge, org: String = origin): Array[Byte] =
    s"""{"type":"webauthn.get","challenge":"$chal","origin":"$org"}""".getBytes("UTF-8")

  test("verifies a full login assertion against a freshly generated key, end to end") {
    val genAlgorithm = js.Dynamic.literal(name = "ECDSA", namedCurve = "P-256")
    val signAlgorithm = js.Dynamic.literal(name = "ECDSA", hash = "SHA-256")
    val authData = authenticatorData(flags = 0x01 | 0x04, signCount = 5L)
    val cdj = clientDataJSON()

    for {
      keyPair <- extras.generateKey(genAlgorithm, true, js.Array("sign", "verify"))
      publicJwk <- extras.exportKey("jwk", keyPair.publicKey.asInstanceOf[CryptoKey])
      publicKey = CoseEc2Key(
        x = Base64Url.decode(publicJwk.x.asInstanceOf[String]),
        y = Base64Url.decode(publicJwk.y.asInstanceOf[String])
      )
      clientDataHash <- Sha256.digest(cdj)
      rawSignatureBuf <- extras.sign(signAlgorithm, keyPair.privateKey.asInstanceOf[CryptoKey], toUint8(authData ++ clientDataHash))
      rawSignature = toBytes(rawSignatureBuf)
      derSignature = DerTestVectors.encodeSignature(rawSignature.take(32), rawSignature.drop(32))
      result <- Assertion.verify(cdj, authData, derSignature, publicKey, previousSignCount = 4L, challenge, origin, rpIdHash)
    } yield result match {
      case Right(success) => assertEquals(success.newSignCount, 5L)
      case Left(reason) => fail(s"expected success, got: $reason")
    }
  }

  test("rejects a replayed (non-increasing) sign counter") {
    val genAlgorithm = js.Dynamic.literal(name = "ECDSA", namedCurve = "P-256")
    val signAlgorithm = js.Dynamic.literal(name = "ECDSA", hash = "SHA-256")
    val authData = authenticatorData(flags = 0x01 | 0x04, signCount = 3L)
    val cdj = clientDataJSON()

    for {
      keyPair <- extras.generateKey(genAlgorithm, true, js.Array("sign", "verify"))
      publicJwk <- extras.exportKey("jwk", keyPair.publicKey.asInstanceOf[CryptoKey])
      publicKey = CoseEc2Key(
        x = Base64Url.decode(publicJwk.x.asInstanceOf[String]),
        y = Base64Url.decode(publicJwk.y.asInstanceOf[String])
      )
      clientDataHash <- Sha256.digest(cdj)
      rawSignatureBuf <- extras.sign(signAlgorithm, keyPair.privateKey.asInstanceOf[CryptoKey], toUint8(authData ++ clientDataHash))
      rawSignature = toBytes(rawSignatureBuf)
      derSignature = DerTestVectors.encodeSignature(rawSignature.take(32), rawSignature.drop(32))
      // previousSignCount (5) >= this assertion's signCount (3) => must be rejected
      result <- Assertion.verify(cdj, authData, derSignature, publicKey, previousSignCount = 5L, challenge, origin, rpIdHash)
    } yield assertEquals(result, Left("sign count did not increase (possible cloned authenticator)"))
  }
}
