package passkey4s.webauthn

import scala.concurrent.{ExecutionContext, Future}

final case class AssertionSuccess(newSignCount: Long)

object Assertion {
  def verify(
      clientDataJSON: Array[Byte],
      authenticatorData: Array[Byte],
      signature: Array[Byte],
      publicKey: CoseEc2Key,
      previousSignCount: Long,
      expectedChallenge: String,
      expectedOrigin: String,
      expectedRpIdHash: Array[Byte]
  )(implicit ec: ExecutionContext): Future[Either[String, AssertionSuccess]] = {
    val clientData = ClientData.parse(clientDataJSON)
    val authData = AuthenticatorData.parse(authenticatorData)

    val syncFailure: Option[String] =
      if (clientData.`type` != "webauthn.get") Some(s"unexpected clientData.type: ${clientData.`type`}")
      else if (clientData.challenge != expectedChallenge) Some("challenge mismatch")
      else if (clientData.origin != expectedOrigin) Some("origin mismatch")
      else if (!authData.rpIdHash.sameElements(expectedRpIdHash)) Some("rpIdHash mismatch")
      else if (!authData.userPresent) Some("user not present")
      else if (!authData.userVerified) Some("user not verified")
      // signCount 0 is common for authenticators that don't implement a counter;
      // only treat a non-zero, non-increasing counter as a cloning signal.
      else if (authData.signCount != 0 && authData.signCount <= previousSignCount)
        Some("sign count did not increase (possible cloned authenticator)")
      else None

    syncFailure match {
      case Some(reason) => Future.successful(Left(reason))
      case None =>
        for {
          clientDataHash <- Sha256.digest(clientDataJSON)
          rawSignature = Der.toRawEcdsaSignature(signature)
          signedData = authenticatorData ++ clientDataHash
          valid <- Es256.verify(publicKey, rawSignature, signedData)
        } yield
          if (valid) Right(AssertionSuccess(authData.signCount))
          else Left("signature verification failed")
    }
  }
}
