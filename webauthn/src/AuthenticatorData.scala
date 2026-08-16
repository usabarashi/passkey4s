package passkey4s.webauthn

final case class AttestedCredentialData(
    aaguid: Array[Byte],
    credentialId: Array[Byte],
    publicKey: CoseEc2Key
)

final case class AuthenticatorData(
    rpIdHash: Array[Byte],
    userPresent: Boolean,
    userVerified: Boolean,
    signCount: Long,
    attestedCredentialData: Option[AttestedCredentialData]
)

object AuthenticatorData {
  private val FlagUserPresent = 0x01
  private val FlagUserVerified = 0x04
  private val FlagAttestedCredentialData = 0x40

  def parse(bytes: Array[Byte]): AuthenticatorData = {
    require(bytes.length >= 37, s"authenticatorData too short: ${bytes.length} bytes")
    val rpIdHash = bytes.slice(0, 32)
    val flags = bytes(32) & 0xff
    var signCount = 0L
    (0 until 4).foreach(i => signCount = (signCount << 8) | (bytes(33 + i) & 0xff))

    val attested =
      if ((flags & FlagAttestedCredentialData) == 0) None
      else {
        var pos = 37
        val aaguid = bytes.slice(pos, pos + 16)
        pos += 16
        val credentialIdLength = ((bytes(pos) & 0xff) << 8) | (bytes(pos + 1) & 0xff)
        pos += 2
        val credentialId = bytes.slice(pos, pos + credentialIdLength)
        pos += credentialIdLength
        val publicKey = Cose.parseEc2Key(bytes, pos)
        Some(AttestedCredentialData(aaguid, credentialId, publicKey))
      }

    AuthenticatorData(
      rpIdHash = rpIdHash,
      userPresent = (flags & FlagUserPresent) != 0,
      userVerified = (flags & FlagUserVerified) != 0,
      signCount = signCount,
      attestedCredentialData = attested
    )
  }
}
