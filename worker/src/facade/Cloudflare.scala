package passkey4s.worker.facade

import scala.scalajs.js
import scala.scalajs.js.annotation._

@js.native
trait CFRequest extends js.Object {
  def url: String = js.native
  def method: String = js.native
}

trait ResponseInit extends js.Object {
  var status: js.UndefOr[Int] = js.undefined
}

@js.native
@JSGlobal("Response")
class CFResponse(body: js.UndefOr[String], init: js.UndefOr[ResponseInit]) extends js.Object

@js.native
trait SqlStorageCursor extends js.Object {
  def toArray(): js.Array[js.Dynamic] = js.native
}

@js.native
trait SqlStorage extends js.Object {
  def exec(query: String, bindings: js.Any*): SqlStorageCursor = js.native
}

@js.native
trait DurableObjectStorage extends js.Object {
  def sql: SqlStorage = js.native
  def setAlarm(scheduledTime: Double): js.Promise[Unit] = js.native
  def deleteAll(): js.Promise[Unit] = js.native
}

@js.native
trait DurableObjectState extends js.Object {
  def storage: DurableObjectStorage = js.native
  def blockConcurrencyWhile(fn: js.Function0[js.Promise[Unit]]): js.Promise[Unit] = js.native
}
