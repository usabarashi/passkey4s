package passkey4s.webauthn

import CborTestVectors._

class CborReaderSuite extends munit.FunSuite {
  test("reads small and multi-byte unsigned ints") {
    assertEquals(new CborReader(uint(0)).readInt(), 0L)
    assertEquals(new CborReader(uint(23)).readInt(), 23L)
    assertEquals(new CborReader(uint(24)).readInt(), 24L)
    assertEquals(new CborReader(uint(255)).readInt(), 255L)
    assertEquals(new CborReader(uint(1000)).readInt(), 1000L)
    assertEquals(new CborReader(uint(100000)).readInt(), 100000L)
  }

  test("reads negative ints") {
    assertEquals(new CborReader(negint(-1)).readInt(), -1L)
    assertEquals(new CborReader(negint(-7)).readInt(), -7L)
    assertEquals(new CborReader(negint(-1000)).readInt(), -1000L)
  }

  test("reads byte strings") {
    val payload = Array[Byte](1, 2, 3, 4, 5)
    assertEquals(new CborReader(bytes(payload)).readBytes().toSeq, payload.toSeq)
  }

  test("reads text strings") {
    assertEquals(new CborReader(text("authData")).readText(), "authData")
    assertEquals(new CborReader(text("")).readText(), "")
  }

  test("reads map header and skips unknown entries") {
    val map = mapHeader(2) ++ text("a") ++ uint(1) ++ text("b") ++ bytes(Array[Byte](9, 9))
    val r = new CborReader(map)
    assertEquals(r.readMapHeader(), 2)
    assertEquals(r.readText(), "a")
    r.skipItem()
    assertEquals(r.readText(), "b")
    assertEquals(r.readBytes().toSeq, Seq[Byte](9, 9))
  }

  test("skipItem skips nested maps and arrays") {
    val nestedMap = mapHeader(1) ++ text("k") ++ (mapHeader(1) ++ uint(1) ++ uint(2))
    val outer = mapHeader(1) ++ text("outer") ++ nestedMap
    val r = new CborReader(outer)
    assertEquals(r.readMapHeader(), 1)
    assertEquals(r.readText(), "outer")
    r.skipItem() // should consume the whole nested map without throwing
    assertEquals(r.position, outer.length)
  }
}
