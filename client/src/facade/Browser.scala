package passkey4s.client.facade

import scala.scalajs.js
import scala.scalajs.js.annotation._

/** Native browser APIs only — no @simplewebauthn/browser, no fetch wrapper
  * library. This is the client-side half of the npm-zero decision.
  */
@js.native
trait FetchResponse extends js.Object {
  def ok: Boolean = js.native
  def status: Int = js.native
  def text(): js.Promise[String] = js.native
}

@js.native
@JSGlobal("fetch")
def fetch(url: String, init: js.Any): js.Promise[FetchResponse] = js.native

@js.native
trait CredentialsContainer extends js.Object {
  def create(options: js.Any): js.Promise[js.Dynamic] = js.native
  def get(options: js.Any): js.Promise[js.Dynamic] = js.native
}

@js.native
trait NavigatorGlobal extends js.Object {
  def credentials: CredentialsContainer = js.native
}

object Navigator {
  def credentials: CredentialsContainer = js.Dynamic.global.navigator.asInstanceOf[NavigatorGlobal].credentials
}
