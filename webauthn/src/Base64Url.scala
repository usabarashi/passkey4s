package passkey4s.webauthn

import scala.scalajs.js

object Base64Url {
  def decode(s: String): Array[Byte] = {
    val standard = s.replace('-', '+').replace('_', '/')
    val pad = (4 - standard.length % 4) % 4
    val padded = standard + ("=" * pad)
    val binary = js.Dynamic.global.atob(padded).asInstanceOf[String]
    Array.tabulate(binary.length)(i => (binary.charAt(i).toInt & 0xff).toByte)
  }

  def encode(bytes: Array[Byte]): String = {
    val binary = new String(bytes.map(b => (b.toInt & 0xff).toChar))
    val b64 = js.Dynamic.global.btoa(binary).asInstanceOf[String]
    b64.replace('+', '-').replace('/', '_').replace("=", "")
  }
}
