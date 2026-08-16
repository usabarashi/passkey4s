package passkey4s.webauthn

final case class RegisteredCredential(credentialId: Array[Byte], publicKey: CoseEc2Key, signCount: Long)

/** Registration (attestation "none") never needs the signature-verifying
  * WebCrypto call, so unlike Assertion this stays fully synchronous and
  * easy to unit test.
  */
object Registration {
  def verify(
      clientDataJSON: Array[Byte],
      attestationObject: Array[Byte],
      expectedChallenge: String,
      expectedOrigin: String,
      expectedRpIdHash: Array[Byte]
  ): Either[String, RegisteredCredential] = {
    val clientData = ClientData.parse(clientDataJSON)
    if (clientData.`type` != "webauthn.create")
      Left(s"unexpected clientData.type: ${clientData.`type`}")
    else if (clientData.challenge != expectedChallenge)
      Left("challenge mismatch")
    else if (clientData.origin != expectedOrigin)
      Left("origin mismatch")
    else {
      val authData = AuthenticatorData.parse(AttestationObject.extractAuthData(attestationObject))
      if (!authData.rpIdHash.sameElements(expectedRpIdHash)) Left("rpIdHash mismatch")
      else if (!authData.userPresent) Left("user not present")
      else if (!authData.userVerified) Left("user not verified")
      else
        authData.attestedCredentialData match {
          case None => Left("missing attested credential data")
          case Some(attested) =>
            Right(RegisteredCredential(attested.credentialId, attested.publicKey, authData.signCount))
        }
    }
  }
}
