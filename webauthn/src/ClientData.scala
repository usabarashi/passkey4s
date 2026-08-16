package passkey4s.webauthn

import scala.scalajs.js

/** clientDataJSON has more fields (crossOrigin, tokenBinding) than this
  * sample needs; only type/challenge/origin are checked. Parsed via the
  * native JSON.parse global rather than a hand-rolled JSON parser.
  */
final case class ClientData(`type`: String, challenge: String, origin: String)

object ClientData {
  def parse(bytes: Array[Byte]): ClientData = {
    val json = js.JSON.parse(new String(bytes, "UTF-8")).asInstanceOf[js.Dynamic]
    ClientData(
      `type` = json.`type`.asInstanceOf[String],
      challenge = json.challenge.asInstanceOf[String],
      origin = json.origin.asInstanceOf[String]
    )
  }
}
