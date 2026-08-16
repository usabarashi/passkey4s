package passkey4s.worker

import scala.scalajs.js
import scala.scalajs.js.annotation._
import passkey4s.worker.facade._

// Spike: prove Scala.js can export a Durable Object class (fetch + alarm)
// and round-trip a value through ctx.storage.sql.exec under wrangler dev.
@JSExportTopLevel("SpikeDO")
class SpikeDO(ctx: DurableObjectState, env: js.Any) {

  ctx.blockConcurrencyWhile(() => {
    ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS spike (id INTEGER PRIMARY KEY, note TEXT)")
    js.Promise.resolve[Unit](())
  })

  @JSExport
  def fetch(request: CFRequest): js.Promise[CFResponse] = {
    ctx.storage.sql.exec("INSERT INTO spike (note) VALUES (?)", "hello-from-scala-js")
    val rows = ctx.storage.sql.exec("SELECT id, note FROM spike").toArray()
    val body = js.JSON.stringify(rows)
    val init = new ResponseInit { status = 200 }
    js.Promise.resolve(new CFResponse(body, init))
  }

  @JSExport
  def alarm(): js.Promise[Unit] = ctx.storage.deleteAll()
}

object Worker {
  @JSExportTopLevel("default")
  val handler: js.Object = new js.Object {
    val fetch: js.Function3[CFRequest, js.Dynamic, js.Dynamic, js.Promise[CFResponse]] =
      (request, env, _) => {
        val id = env.SPIKE_DO.idFromName("spike-user")
        val stub = env.SPIKE_DO.get(id)
        stub.fetch(request).asInstanceOf[js.Promise[CFResponse]]
      }
  }
}
