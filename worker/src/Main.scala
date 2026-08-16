package passkey4s.worker

import scala.concurrent.ExecutionContext.Implicits.global
import scala.scalajs.js
import scala.scalajs.js.JSConverters._
import scala.scalajs.js.Thenable.Implicits._
import scala.scalajs.js.annotation._
import passkey4s.worker.facade._

private val knownRoutes =
  Set("/register/options", "/register/verify", "/login/options", "/login/verify")

object Worker {
  private def jsonError(status: Int, reason: String): CFResponse = {
    val init = new ResponseInit {}
    init.status = status
    init.headers = js.Dictionary("Content-Type" -> "application/json")
    new CFResponse(js.JSON.stringify(js.Dynamic.literal(success = false, reason = reason)), init)
  }

  @JSExportTopLevel("default")
  val handler: js.Object = new js.Object {
    val fetch: js.Function3[CFRequest, js.Dynamic, js.Dynamic, js.Promise[CFResponse]] =
      (request, env, _) => {
        val path = new NativeUrl(request.url).pathname
        val result =
          if (!knownRoutes.contains(path))
            env.ASSETS.fetch(request).asInstanceOf[js.Promise[CFResponse]].toFuture
          else
            request
              .clone()
              .text()
              .toFuture
              .map { text =>
                val body = js.JSON.parse(text).asInstanceOf[js.Dynamic]
                body.username.asInstanceOf[js.UndefOr[String]].toOption
              }
              .flatMap {
                case None => scala.concurrent.Future.successful(jsonError(400, "missing \"username\""))
                case Some(username) if username.trim.isEmpty =>
                  scala.concurrent.Future.successful(jsonError(400, "missing \"username\""))
                case Some(username) =>
                  val id = env.USER_DO.asInstanceOf[DurableObjectNamespace].idFromName(username)
                  val stub = env.USER_DO.asInstanceOf[DurableObjectNamespace].get(id)
                  stub.fetch(request).toFuture
              }
              .recover { case e: Throwable => jsonError(500, s"internal error: ${e.getMessage}") }
        result.toJSPromise
      }
  }
}
