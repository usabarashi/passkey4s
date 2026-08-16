package passkey4s.webauthn

import scala.scalajs.js.typedarray.{ArrayBuffer, Uint8Array}

/** Conversions between Scala Array[Byte] and the typed-array shapes native
  * browser/Workers APIs (fetch bodies, WebCrypto, WebAuthn) actually use.
  */
object BytesJs {
  def toUint8Array(bytes: Array[Byte]): Uint8Array = {
    val arr = new Uint8Array(bytes.length)
    var i = 0
    while (i < bytes.length) {
      arr(i) = (bytes(i) & 0xff).toShort
      i += 1
    }
    arr
  }

  def fromUint8Array(view: Uint8Array): Array[Byte] =
    Array.tabulate(view.length)(i => view(i).toByte)

  def fromArrayBuffer(buf: ArrayBuffer): Array[Byte] = fromUint8Array(new Uint8Array(buf))

  def toArrayBuffer(bytes: Array[Byte]): ArrayBuffer = toUint8Array(bytes).buffer
}
