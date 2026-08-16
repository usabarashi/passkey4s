package passkey4s.client

import cats.effect.IO
import tyrian.*
import tyrian.Html.*
import scala.scalajs.js.annotation._

enum Status {
  case Idle
  case Working
  case Done(message: String, ok: Boolean)
}

case class Model(username: String, status: Status)

enum Msg {
  case NoOp
  case UsernameChanged(value: String)
  case RegisterClicked
  case LoginClicked
  case Completed(result: Either[String, String])
}

object Main extends TyrianIOApp[Msg, Model] {
  // Single-page app, no client-side routing (Q8/Q9 decisions).
  def router: Location => Msg = _ => Msg.NoOp

  def init(flags: Map[String, String]): (Model, Cmd[IO, Msg]) =
    (Model("", Status.Idle), Cmd.None)

  def update(model: Model): Msg => (Model, Cmd[IO, Msg]) = {
    case Msg.NoOp =>
      (model, Cmd.None)

    case Msg.UsernameChanged(value) =>
      (model.copy(username = value), Cmd.None)

    case Msg.RegisterClicked if model.username.trim.nonEmpty =>
      (model.copy(status = Status.Working), Cmd.Run(Api.register(model.username), Msg.Completed.apply))

    case Msg.LoginClicked if model.username.trim.nonEmpty =>
      (model.copy(status = Status.Working), Cmd.Run(Api.login(model.username), Msg.Completed.apply))

    case Msg.RegisterClicked | Msg.LoginClicked =>
      (model.copy(status = Status.Done("Please enter a username first.", ok = false)), Cmd.None)

    case Msg.Completed(Right(message)) =>
      (model.copy(status = Status.Done(message, ok = true)), Cmd.None)

    case Msg.Completed(Left(reason)) =>
      (model.copy(status = Status.Done(reason, ok = false)), Cmd.None)
  }

  def view(model: Model): Html[Msg] =
    div()(
      h1()(text("passkey4s")),
      p()(
        text(
          "This is a demo site — the server resets every day. If login with an old " +
            "username fails, delete the saved passkey on your device and register again."
        )
      ),
      input(placeholder := "username", value := model.username, onInput(Msg.UsernameChanged.apply)),
      button(onClick(Msg.RegisterClicked))(text("Register")),
      button(onClick(Msg.LoginClicked))(text("Log in")),
      div()(text(statusText(model.status)))
    )

  private def statusText(status: Status): String = status match {
    case Status.Idle => ""
    case Status.Working => "Working…"
    case Status.Done(message, _) => message
  }

  def subscriptions(model: Model): Sub[IO, Msg] = Sub.None

  @JSExportTopLevel("main")
  def main(): Unit = launch("app")
}
