package passkey4s.webauthn

import CborTestVectors._

class AttestationObjectSuite extends munit.FunSuite {
  test("extracts authData, ignoring fmt and an empty attStmt (attestation none)") {
    val authData = Array.tabulate(37)(i => i.toByte)
    val obj =
      mapHeader(3) ++
        text("fmt") ++ text("none") ++
        text("attStmt") ++ mapHeader(0) ++
        text("authData") ++ bytes(authData)

    assertEquals(AttestationObject.extractAuthData(obj).toSeq, authData.toSeq)
  }

  test("works regardless of field order") {
    val authData = Array.fill(37)(9.toByte)
    val obj =
      mapHeader(3) ++
        text("authData") ++ bytes(authData) ++
        text("fmt") ++ text("none") ++
        text("attStmt") ++ mapHeader(0)

    assertEquals(AttestationObject.extractAuthData(obj).toSeq, authData.toSeq)
  }

  test("fails clearly when authData is missing") {
    val obj = mapHeader(1) ++ text("fmt") ++ text("none")
    intercept[IllegalArgumentException](AttestationObject.extractAuthData(obj))
  }
}
