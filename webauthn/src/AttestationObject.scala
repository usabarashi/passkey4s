package passkey4s.webauthn

/** Only the `authData` field is extracted: this sample requires
  * `attestation: "none"`, so `fmt`/`attStmt` are read past but never
  * interpreted.
  */
object AttestationObject {
  def extractAuthData(bytes: Array[Byte]): Array[Byte] = {
    val r = new CborReader(bytes)
    val n = r.readMapHeader()
    var authData: Array[Byte] = null
    (0 until n).foreach { _ =>
      r.readText() match {
        case "authData" => authData = r.readBytes()
        case _ => r.skipItem()
      }
    }
    require(authData != null, "attestationObject missing authData")
    authData
  }
}
