package passkey4s.client

import cats.effect.IO
import scala.scalajs.js
import scala.scalajs.js.typedarray.ArrayBuffer
import passkey4s.client.facade._
import passkey4s.webauthn.{Base64Url, BytesJs}

object Api {
  private def postJson(path: String, body: js.Any): IO[js.Dynamic] = {
    val init = js.Dynamic.literal(
      method = "POST",
      headers = js.Dictionary("Content-Type" -> "application/json"),
      body = js.JSON.stringify(body)
    )
    for {
      response <- IO.fromPromise(IO(fetch(path, init)))
      text <- IO.fromPromise(IO(response.text()))
    } yield js.JSON.parse(text).asInstanceOf[js.Dynamic]
  }

  private def encodeField(buf: js.Any): String =
    Base64Url.encode(BytesJs.fromArrayBuffer(buf.asInstanceOf[ArrayBuffer]))

  private def decodeToArrayBuffer(b64: String): ArrayBuffer =
    BytesJs.toArrayBuffer(Base64Url.decode(b64))

  private def resultToEither(result: js.Dynamic, successMessage: String): Either[String, String] =
    if (result.success.asInstanceOf[Boolean]) Right(successMessage)
    else Left(result.reason.asInstanceOf[js.UndefOr[String]].getOrElse("unknown error"))

  private def toCreationOptions(options: js.Dynamic): js.Dynamic = {
    val publicKey = js.Dynamic.literal(
      challenge = decodeToArrayBuffer(options.challenge.asInstanceOf[String]),
      rp = options.rp,
      user = js.Dynamic.literal(
        id = decodeToArrayBuffer(options.user.id.asInstanceOf[String]),
        name = options.user.name,
        displayName = options.user.displayName
      ),
      pubKeyCredParams = options.pubKeyCredParams,
      authenticatorSelection = options.authenticatorSelection,
      attestation = options.attestation
    )
    js.Dynamic.literal(publicKey = publicKey)
  }

  private def toRequestOptions(options: js.Dynamic): js.Dynamic = {
    val allowCredentials = options.allowCredentials
      .asInstanceOf[js.Array[js.Dynamic]]
      .map(cred => js.Dynamic.literal(`type` = cred.`type`, id = decodeToArrayBuffer(cred.id.asInstanceOf[String])))
    val publicKey = js.Dynamic.literal(
      challenge = decodeToArrayBuffer(options.challenge.asInstanceOf[String]),
      rpId = options.rpId,
      allowCredentials = allowCredentials,
      userVerification = options.userVerification
    )
    js.Dynamic.literal(publicKey = publicKey)
  }

  def register(username: String): IO[Either[String, String]] =
    for {
      options <- postJson("/register/options", js.Dynamic.literal(username = username))
      credential <- IO.fromPromise(IO(Navigator.credentials.create(toCreationOptions(options))))
      verifyBody = js.Dynamic.literal(
        username = username,
        clientDataJSON = encodeField(credential.response.clientDataJSON),
        attestationObject = encodeField(credential.response.attestationObject)
      )
      result <- postJson("/register/verify", verifyBody)
    } yield resultToEither(result, "Registered! You can now log in with this passkey.")

  def login(username: String): IO[Either[String, String]] =
    for {
      options <- postJson("/login/options", js.Dynamic.literal(username = username))
      credential <- IO.fromPromise(IO(Navigator.credentials.get(toRequestOptions(options))))
      verifyBody = js.Dynamic.literal(
        username = username,
        clientDataJSON = encodeField(credential.response.clientDataJSON),
        authenticatorData = encodeField(credential.response.authenticatorData),
        signature = encodeField(credential.response.signature)
      )
      result <- postJson("/login/verify", verifyBody)
    } yield resultToEither(result, "Logged in!")
}
