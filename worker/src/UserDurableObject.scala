package passkey4s.worker

import scala.concurrent.ExecutionContext.Implicits.global
import scala.scalajs.js
import scala.scalajs.js.JSConverters._
import scala.scalajs.js.Thenable.Implicits._
import scala.scalajs.js.annotation._
import passkey4s.worker.facade._
import passkey4s.webauthn._

/** One Durable Object per username (Q3), holding at most one credential
  * (Q11) plus a single transient challenge row (Q10). The alarm slot is
  * reserved solely for the 24h self-reset (Q4) — challenge expiry is a
  * plain `expires_at` check at verify time instead of a second alarm.
  */
@JSExportTopLevel("UserDurableObject")
class UserDurableObject(ctx: DurableObjectState, env: js.Any) {
  private val rpId: String = env.asInstanceOf[Env].RP_ID
  private val origin: String = env.asInstanceOf[Env].ORIGIN

  ctx.blockConcurrencyWhile(() => {
    Storage.ensureSchema(ctx.storage)
    js.Promise.resolve[Unit](())
  })

  private def jsonResponse(status: Int, body: js.Any): CFResponse = {
    val init = new ResponseInit {}
    init.status = status
    init.headers = js.Dictionary("Content-Type" -> "application/json")
    new CFResponse(js.JSON.stringify(body), init)
  }

  private def failure(reason: String, status: Int = 400): CFResponse =
    jsonResponse(status, js.Dynamic.literal(success = false, reason = reason))

  private val challengeTtlMillis: Double = 5 * 60 * 1000
  private val selfResetDelayMillis: Double = 24 * 60 * 60 * 1000

  private def rpIdHash(): scala.concurrent.Future[Array[Byte]] =
    Sha256.digest(rpId.getBytes("UTF-8"))

  private def handleRegisterOptions(username: String): scala.concurrent.Future[CFResponse] = {
    val challenge = SecureRandom.base64UrlToken()
    Storage.upsertChallenge(ctx.storage, challenge, "registration", js.Date.now() + challengeTtlMillis)
    val userId = Base64Url.encode(username.getBytes("UTF-8"))
    scala.concurrent.Future.successful(
      jsonResponse(
        200,
        js.Dynamic.literal(
          challenge = challenge,
          rp = js.Dynamic.literal(id = rpId, name = "passkey4s"),
          user = js.Dynamic.literal(id = userId, name = username, displayName = username),
          pubKeyCredParams = js.Array(js.Dynamic.literal(`type` = "public-key", alg = -7)),
          authenticatorSelection = js.Dynamic.literal(userVerification = "required"),
          attestation = "none"
        )
      )
    )
  }

  private def handleRegisterVerify(body: js.Dynamic): scala.concurrent.Future[CFResponse] = {
    Storage.readChallenge(ctx.storage) match {
      case None => scala.concurrent.Future.successful(failure("no pending registration challenge"))
      case Some(stored) if stored.ceremony != "registration" =>
        scala.concurrent.Future.successful(failure("no pending registration challenge"))
      case Some(stored) if stored.expiresAt < js.Date.now() =>
        Storage.deleteChallenge(ctx.storage)
        scala.concurrent.Future.successful(failure("registration challenge expired, please try again"))
      case Some(stored) =>
        rpIdHash().map { expectedRpIdHash =>
          val clientDataJSON = Base64Url.decode(body.clientDataJSON.asInstanceOf[String])
          val attestationObject = Base64Url.decode(body.attestationObject.asInstanceOf[String])
          Registration.verify(clientDataJSON, attestationObject, stored.valueB64, origin, expectedRpIdHash) match {
            case Right(cred) =>
              Storage.upsertCredential(
                ctx.storage,
                Base64Url.encode(cred.credentialId),
                Base64Url.encode(cred.publicKey.x),
                Base64Url.encode(cred.publicKey.y),
                cred.signCount
              )
              Storage.deleteChallenge(ctx.storage)
              ctx.storage.setAlarm(js.Date.now() + selfResetDelayMillis)
              jsonResponse(200, js.Dynamic.literal(success = true))
            case Left(reason) => failure(reason)
          }
        }
    }
  }

  private def handleLoginOptions(): scala.concurrent.Future[CFResponse] =
    Storage.readCredential(ctx.storage) match {
      case None => scala.concurrent.Future.successful(failure("no passkey registered for this username", status = 404))
      case Some(cred) =>
        val challenge = SecureRandom.base64UrlToken()
        Storage.upsertChallenge(ctx.storage, challenge, "authentication", js.Date.now() + challengeTtlMillis)
        scala.concurrent.Future.successful(
          jsonResponse(
            200,
            js.Dynamic.literal(
              challenge = challenge,
              rpId = rpId,
              allowCredentials = js.Array(js.Dynamic.literal(`type` = "public-key", id = cred.credentialIdB64)),
              userVerification = "required"
            )
          )
        )
    }

  private def handleLoginVerify(body: js.Dynamic): scala.concurrent.Future[CFResponse] = {
    (Storage.readCredential(ctx.storage), Storage.readChallenge(ctx.storage)) match {
      case (None, _) => scala.concurrent.Future.successful(failure("no passkey registered for this username", status = 404))
      case (_, None) => scala.concurrent.Future.successful(failure("no pending login challenge"))
      case (_, Some(stored)) if stored.ceremony != "authentication" =>
        scala.concurrent.Future.successful(failure("no pending login challenge"))
      case (_, Some(stored)) if stored.expiresAt < js.Date.now() =>
        Storage.deleteChallenge(ctx.storage)
        scala.concurrent.Future.successful(failure("login challenge expired, please try again"))
      case (Some(cred), Some(stored)) =>
        rpIdHash().flatMap { expectedRpIdHash =>
          val clientDataJSON = Base64Url.decode(body.clientDataJSON.asInstanceOf[String])
          val authenticatorData = Base64Url.decode(body.authenticatorData.asInstanceOf[String])
          val signature = Base64Url.decode(body.signature.asInstanceOf[String])
          val publicKey = CoseEc2Key(Base64Url.decode(cred.publicKeyXB64), Base64Url.decode(cred.publicKeyYB64))
          Assertion
            .verify(clientDataJSON, authenticatorData, signature, publicKey, cred.signCount, stored.valueB64, origin, expectedRpIdHash)
            .map {
              case Right(success) =>
                Storage.updateSignCount(ctx.storage, success.newSignCount)
                Storage.deleteChallenge(ctx.storage)
                jsonResponse(200, js.Dynamic.literal(success = true))
              case Left(reason) => failure(reason)
            }
        }
    }
  }

  @JSExport
  def fetch(request: CFRequest): js.Promise[CFResponse] = {
    val path = new NativeUrl(request.url).pathname
    val result = request
      .text()
      .toFuture
      .flatMap { text =>
        val body = js.JSON.parse(text).asInstanceOf[js.Dynamic]
        path match {
          case "/register/options" => handleRegisterOptions(body.username.asInstanceOf[String])
          case "/register/verify" => handleRegisterVerify(body)
          case "/login/options" => handleLoginOptions()
          case "/login/verify" => handleLoginVerify(body)
          case other => scala.concurrent.Future.successful(failure(s"unknown route: $other", status = 404))
        }
      }
      .recover { case e: Throwable => failure(s"internal error: ${e.getMessage}", status = 500) }
    result.toJSPromise
  }

  @JSExport
  def alarm(): js.Promise[Unit] = ctx.storage.deleteAll()
}
