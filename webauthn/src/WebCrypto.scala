package passkey4s.webauthn

import scala.scalajs.js

/** Facade for the native WebCrypto SubtleCrypto API, available as a global
  * in both browsers and the Cloudflare Workers runtime — no npm dependency.
  */
@js.native
trait CryptoKey extends js.Object

@js.native
trait SubtleCrypto extends js.Object {
  def importKey(
      format: String,
      keyData: js.Any,
      algorithm: js.Any,
      extractable: Boolean,
      keyUsages: js.Array[String]
  ): js.Promise[CryptoKey] = js.native

  def verify(algorithm: js.Any, key: CryptoKey, signature: js.typedarray.Uint8Array, data: js.typedarray.Uint8Array): js.Promise[Boolean] =
    js.native

  def digest(algorithm: String, data: js.typedarray.Uint8Array): js.Promise[js.typedarray.ArrayBuffer] = js.native
}

@js.native
trait CryptoGlobal extends js.Object {
  def subtle: SubtleCrypto = js.native
}

object WebCrypto {
  def subtle: SubtleCrypto = js.Dynamic.global.crypto.asInstanceOf[CryptoGlobal].subtle
}
