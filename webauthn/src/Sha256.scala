package passkey4s.webauthn

import scala.concurrent.{ExecutionContext, Future}
import scala.scalajs.js.Thenable.Implicits._
import scala.scalajs.js.typedarray.Uint8Array

object Sha256 {
  def digest(bytes: Array[Byte])(implicit ec: ExecutionContext): Future[Array[Byte]] = {
    val input = new Uint8Array(bytes.length)
    var i = 0
    while (i < bytes.length) {
      input(i) = (bytes(i) & 0xff).toShort
      i += 1
    }
    WebCrypto.subtle.digest("SHA-256", input).map { buf =>
      val view = new Uint8Array(buf)
      Array.tabulate(view.length)(i => view(i).toByte)
    }
  }
}
