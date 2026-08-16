#!/usr/bin/env node
// Exercises the real HTTP + Durable Object + SQLite path against a running
// `wrangler dev` instance, which the MUnit suite (webauthn/test) cannot
// reach since it never runs inside the Workers runtime. attestation "none"
// means Registration.verify never checks a signature, so the registration
// ceremony can be fully synthesized here (CBOR/authenticatorData built by
// hand, mirroring RegistrationSuite.scala); the login ceremony uses a real
// ECDSA P-256 key via Node's WebCrypto so the DER<->raw signature path gets
// exercised for real, mirroring AssertionSuite.scala.
//
// Usage: node scripts/e2e-smoke-test.mjs [baseUrl]

import assert from "node:assert/strict";
import crypto from "node:crypto";

const BASE = process.argv[2] ?? "http://localhost:18787";
const RP_ID = "localhost";
const ORIGIN = "http://localhost:18787";
const { subtle } = crypto.webcrypto;

function cborHead(majorType, arg) {
  const first = majorType << 5;
  if (arg < 24) return Buffer.from([first | arg]);
  if (arg < 256) return Buffer.from([first | 24, arg]);
  if (arg < 65536) return Buffer.from([first | 25, (arg >> 8) & 0xff, arg & 0xff]);
  return Buffer.from([
    first | 26,
    (arg >>> 24) & 0xff,
    (arg >>> 16) & 0xff,
    (arg >>> 8) & 0xff,
    arg & 0xff,
  ]);
}
const cborUint = (n) => cborHead(0, n);
const cborNegint = (n) => cborHead(1, -1 - n);
const cborBytes = (b) => Buffer.concat([cborHead(2, b.length), b]);
const cborText = (s) => {
  const utf8 = Buffer.from(s, "utf8");
  return Buffer.concat([cborHead(3, utf8.length), utf8]);
};
const cborMapHeader = (n) => cborHead(5, n);

function coseEc2Key(x, y) {
  return Buffer.concat([
    cborMapHeader(5),
    cborUint(1),
    cborUint(2),
    cborUint(3),
    cborNegint(-7),
    cborNegint(-1),
    cborUint(1),
    cborNegint(-2),
    cborBytes(x),
    cborNegint(-3),
    cborBytes(y),
  ]);
}

function authenticatorData({ rpIdHash, flags, signCount, attested }) {
  const signCountBe32 = Buffer.alloc(4);
  signCountBe32.writeUInt32BE(signCount, 0);
  let buf = Buffer.concat([rpIdHash, Buffer.from([flags]), signCountBe32]);
  if (attested) {
    const credIdLen = Buffer.alloc(2);
    credIdLen.writeUInt16BE(attested.credentialId.length, 0);
    buf = Buffer.concat([
      buf,
      attested.aaguid,
      credIdLen,
      attested.credentialId,
      coseEc2Key(attested.publicKey.x, attested.publicKey.y),
    ]);
  }
  return buf;
}

function attestationObjectNone(authData) {
  return Buffer.concat([
    cborMapHeader(3),
    cborText("fmt"),
    cborText("none"),
    cborText("attStmt"),
    cborMapHeader(0),
    cborText("authData"),
    cborBytes(authData),
  ]);
}

function derEncodeInteger(bytes) {
  const needsLeadingZero = bytes.length > 0 && (bytes[0] & 0x80) !== 0;
  const content = needsLeadingZero ? Buffer.concat([Buffer.from([0]), bytes]) : bytes;
  return Buffer.concat([Buffer.from([0x02, content.length]), content]);
}
function derEncodeSignature(r, s) {
  const body = Buffer.concat([derEncodeInteger(r), derEncodeInteger(s)]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

async function postJson(path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  return { ok: res.ok, status: res.status, json };
}

async function generateKeyAndPublicXY() {
  const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await subtle.exportKey("jwk", keyPair.publicKey);
  return { keyPair, x: Buffer.from(jwk.x, "base64url"), y: Buffer.from(jwk.y, "base64url") };
}

async function register(username) {
  const { keyPair, x, y } = await generateKeyAndPublicXY();
  const credentialId = crypto.randomBytes(16);
  const aaguid = Buffer.alloc(16, 0);

  const options = await postJson("/register/options", { username });
  assert.ok(options.ok, `register/options failed: ${JSON.stringify(options.json)}`);

  const clientDataJSON = Buffer.from(
    JSON.stringify({ type: "webauthn.create", challenge: options.json.challenge, origin: ORIGIN })
  );
  const rpIdHash = crypto.createHash("sha256").update(RP_ID).digest();
  const authData = authenticatorData({
    rpIdHash,
    flags: 0x01 | 0x04 | 0x40, // UP + UV + attested credential data
    signCount: 0,
    attested: { aaguid, credentialId, publicKey: { x, y } },
  });
  const attestationObject = attestationObjectNone(authData);

  const verify = await postJson("/register/verify", {
    username,
    clientDataJSON: clientDataJSON.toString("base64url"),
    attestationObject: attestationObject.toString("base64url"),
  });
  assert.ok(verify.ok && verify.json.success, `register/verify failed: ${JSON.stringify(verify.json)}`);
  return keyPair;
}

async function login(username, keyPair, signCount) {
  const options = await postJson("/login/options", { username });
  assert.ok(options.ok, `login/options failed: ${JSON.stringify(options.json)}`);

  const clientDataJSON = Buffer.from(
    JSON.stringify({ type: "webauthn.get", challenge: options.json.challenge, origin: ORIGIN })
  );
  const rpIdHash = crypto.createHash("sha256").update(RP_ID).digest();
  const authData = authenticatorData({ rpIdHash, flags: 0x01 | 0x04, signCount });
  const clientDataHash = crypto.createHash("sha256").update(clientDataJSON).digest();
  const signedData = Buffer.concat([authData, clientDataHash]);
  const rawSignature = Buffer.from(
    await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, signedData)
  );
  const derSignature = derEncodeSignature(rawSignature.subarray(0, 32), rawSignature.subarray(32, 64));

  const verify = await postJson("/login/verify", {
    username,
    clientDataJSON: clientDataJSON.toString("base64url"),
    authenticatorData: authData.toString("base64url"),
    signature: derSignature.toString("base64url"),
  });
  assert.ok(verify.ok && verify.json.success, `login/verify failed: ${JSON.stringify(verify.json)}`);
}

async function main() {
  const username = `e2e-user-${crypto.randomBytes(4).toString("hex")}`;

  await register(username);
  console.log("[ok] registration");

  // Re-register the same username to exercise Storage.upsertCredential's
  // ON CONFLICT (id) DO UPDATE path, not just the first INSERT.
  const secondKeyPair = await register(username);
  console.log("[ok] re-registration (credential upsert)");

  await login(username, secondKeyPair, 1);
  console.log("[ok] login");

  const unregistered = await postJson("/login/options", { username: `nobody-${Date.now()}` });
  assert.equal(unregistered.status, 404, "expected 404 for an unregistered username");
  console.log("[ok] login/options 404s for an unregistered username");

  console.log("\nAll smoke tests passed.");
}

main().catch((err) => {
  console.error("[fail]", err.message);
  process.exit(1);
});
