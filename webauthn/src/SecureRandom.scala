package passkey4s.webauthn

import scala.scalajs.js
import scala.scalajs.js.typedarray.Uint8Array

@js.native
trait CryptoRandomGlobal extends js.Object {
  def getRandomValues(array: Uint8Array): Uint8Array = js.native
}

/** crypto.getRandomValues is a native Web Platform API (browsers and
  * Workers both implement it) — no npm dependency needed for challenge
  * generation.
  */
object SecureRandom {
  private def global: CryptoRandomGlobal = js.Dynamic.global.crypto.asInstanceOf[CryptoRandomGlobal]

  def bytes(byteLength: Int): Array[Byte] = {
    val arr = new Uint8Array(byteLength)
    global.getRandomValues(arr)
    Array.tabulate(byteLength)(i => arr(i).toByte)
  }

  def base64UrlToken(byteLength: Int = 32): String = Base64Url.encode(bytes(byteLength))
}
