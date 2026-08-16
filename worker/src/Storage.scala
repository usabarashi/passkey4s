package passkey4s.worker

import passkey4s.worker.facade._

/** Everything here is stored as base64url TEXT rather than BLOB — this
  * sidesteps ambiguity around exactly which JS type (ArrayBuffer? Uint8Array?)
  * the DO SQLite binding returns for BLOB columns, in favor of the
  * already-tested Base64Url codec from the webauthn module.
  */
final case class StoredCredential(
    credentialIdB64: String,
    publicKeyXB64: String,
    publicKeyYB64: String,
    signCount: Long
)

final case class StoredChallenge(valueB64: String, ceremony: String, expiresAt: Double)

object Storage {
  def ensureSchema(storage: DurableObjectStorage): Unit = {
    storage.sql.exec(
      """CREATE TABLE IF NOT EXISTS credential (
        |  id INTEGER PRIMARY KEY CHECK (id = 1),
        |  credential_id TEXT NOT NULL,
        |  public_key_x TEXT NOT NULL,
        |  public_key_y TEXT NOT NULL,
        |  sign_count INTEGER NOT NULL
        |)""".stripMargin
    )
    storage.sql.exec(
      """CREATE TABLE IF NOT EXISTS challenge (
        |  id INTEGER PRIMARY KEY CHECK (id = 1),
        |  value TEXT NOT NULL,
        |  ceremony TEXT NOT NULL,
        |  expires_at REAL NOT NULL
        |)""".stripMargin
    )
  }

  def readCredential(storage: DurableObjectStorage): Option[StoredCredential] = {
    val rows = storage.sql
      .exec("SELECT credential_id, public_key_x, public_key_y, sign_count FROM credential WHERE id = 1")
      .toArray()
    if (rows.length == 0) None
    else {
      val row = rows(0)
      Some(
        StoredCredential(
          credentialIdB64 = row.credential_id.asInstanceOf[String],
          publicKeyXB64 = row.public_key_x.asInstanceOf[String],
          publicKeyYB64 = row.public_key_y.asInstanceOf[String],
          signCount = row.sign_count.asInstanceOf[Double].toLong
        )
      )
    }
  }

  def upsertCredential(
      storage: DurableObjectStorage,
      credentialIdB64: String,
      publicKeyXB64: String,
      publicKeyYB64: String,
      signCount: Long
  ): Unit =
    storage.sql.exec(
      """INSERT INTO credential (id, credential_id, public_key_x, public_key_y, sign_count)
        |VALUES (1, ?, ?, ?, ?)
        |ON CONFLICT (id) DO UPDATE SET
        |  credential_id = excluded.credential_id,
        |  public_key_x = excluded.public_key_x,
        |  public_key_y = excluded.public_key_y,
        |  sign_count = excluded.sign_count""".stripMargin,
      credentialIdB64,
      publicKeyXB64,
      publicKeyYB64,
      signCount.toDouble
    )

  def updateSignCount(storage: DurableObjectStorage, signCount: Long): Unit =
    storage.sql.exec("UPDATE credential SET sign_count = ? WHERE id = 1", signCount.toDouble)

  def readChallenge(storage: DurableObjectStorage): Option[StoredChallenge] = {
    val rows = storage.sql.exec("SELECT value, ceremony, expires_at FROM challenge WHERE id = 1").toArray()
    if (rows.length == 0) None
    else {
      val row = rows(0)
      Some(
        StoredChallenge(
          valueB64 = row.value.asInstanceOf[String],
          ceremony = row.ceremony.asInstanceOf[String],
          expiresAt = row.expires_at.asInstanceOf[Double]
        )
      )
    }
  }

  def upsertChallenge(storage: DurableObjectStorage, value: String, ceremony: String, expiresAt: Double): Unit =
    storage.sql.exec(
      """INSERT INTO challenge (id, value, ceremony, expires_at)
        |VALUES (1, ?, ?, ?)
        |ON CONFLICT (id) DO UPDATE SET
        |  value = excluded.value,
        |  ceremony = excluded.ceremony,
        |  expires_at = excluded.expires_at""".stripMargin,
      value,
      ceremony,
      expiresAt
    )

  def deleteChallenge(storage: DurableObjectStorage): Unit =
    storage.sql.exec("DELETE FROM challenge WHERE id = 1")
}
