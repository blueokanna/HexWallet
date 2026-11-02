#ifndef HEXWALLET_SE051_APDU_H
#define HEXWALLET_SE051_APDU_H

#include <stddef.h>
#include <stdint.h>

namespace hexwallet
{

  // APDU encoding for the NXP SE05x / SE051 applet ("SSS"), the one
  // plug-and-trust talks to. Until now this tree had no command bytes at all:
  // Se051Provisioning took abstract callbacks because WriteECCurve's layout was
  // unknown, and the in-card BIP32 HMAC had no command.
  //
  // Every constant and layout below is transcribed from NXP's public SDK
  // (https://github.com/NXP/plug-and-trust), files named next to each group.
  // The repo is a slim package but it carries the generated APDU layer:
  //   hostlib/hostLib/inc/se05x_tlv.h          CLA, TLV helpers
  //   hostlib/hostLib/inc/se05x_enums.h        INS/P1/P2/TAG/curve tables
  //   hostlib/hostLib/inc/se05x_const.h        object ranges, policy bits
  //   hostlib/hostLib/inc/sm_const.h           applet AID
  //   hostlib/hostLib/se05x_03_xx_xx/se05x_APDU_impl.h
  //                                            the literal `tlvHeader_t hdr`
  //                                            line for each command
  //   hostlib/hostLib/se05x/src/se05x_tlv.c    TLV wire encoding
  //   hostlib/hostLib/se05x/src/se05x_ECC_curves.c
  //                                            order of the curve parameters
  //
  // What is NOT public and is therefore not guessed: the SE05x/SE051 APDU
  // specification itself (status words beyond the usual 0x9000/0x6A80/0x6A88/
  // 0x6982, policy semantics, per-part curve entitlement). The builders below
  // encode commands; nothing here claims a card accepts them until a real
  // SE051C2 has answered.

  // se05x_tlv.h:30 `#define kSE05x_CLA 0x80`
  constexpr uint8_t kSe051Cla = 0x80;
  // nxScp03_Const.h: CLA_GP_7816 | CLA_GP_SECURITY_BIT. The applet commands
  // themselves keep CLA 0x80; 0x84 belongs to the GP SCP03 APDUs.
  constexpr uint8_t kSe051ClaPlatformScp = 0x84;

  // se05x_enums.h:96-123. INS is a bitfield, not a per-command enum:
  // 3 character bits (transient / auth object / attest) plus a 5-bit
  // instruction. "CreateECCurve" is INS_WRITE with P1_CURVE.
  constexpr uint8_t kSe051InsWrite = 0x01;
  constexpr uint8_t kSe051InsRead = 0x02;
  constexpr uint8_t kSe051InsCrypto = 0x03;
  constexpr uint8_t kSe051InsMgmt = 0x04;

  // se05x_enums.h:125-167.
  constexpr uint8_t kSe051P1Default = 0x00;
  constexpr uint8_t kSe051P1Ec = 0x01;
  constexpr uint8_t kSe051P1Hmac = 0x05;
  constexpr uint8_t kSe051P1Curve = 0x0b;
  constexpr uint8_t kSe051P1Signature = 0x0c;
  constexpr uint8_t kSe051P1Mac = 0x0d;
  constexpr uint8_t kSe051P1Public = 0x20;
  constexpr uint8_t kSe051P1Private = 0x40;
  constexpr uint8_t kSe051P1KeyPair = 0x60;

  // se05x_enums.h:169-256.
  constexpr uint8_t kSe051P2Default = 0x00;
  constexpr uint8_t kSe051P2Create = 0x04;
  constexpr uint8_t kSe051P2Sign = 0x09;
  constexpr uint8_t kSe051P2Dh = 0x0f;
  constexpr uint8_t kSe051P2SessionCreate = 0x1b;
  constexpr uint8_t kSe051P2SessionPolicy = 0x1f;
  constexpr uint8_t kSe051P2Version = 0x20;
  constexpr uint8_t kSe051P2List = 0x25;
  constexpr uint8_t kSe051P2SessionUserId = 0x2c;
  constexpr uint8_t kSe051P2Param = 0x40;
  constexpr uint8_t kSe051P2GenerateOneShot = 0x45;
  constexpr uint8_t kSe051P2Random = 0x49;

  // se05x_enums.h:285-319.
  constexpr uint8_t kSe051TagSessionId = 0x10;
  constexpr uint8_t kSe051TagPolicy = 0x11;
  constexpr uint8_t kSe051TagMaxAttempts = 0x12;
  constexpr uint8_t kSe051Tag1 = 0x41;
  constexpr uint8_t kSe051Tag2 = 0x42;
  constexpr uint8_t kSe051Tag3 = 0x43;
  constexpr uint8_t kSe051Tag4 = 0x44;
  constexpr uint8_t kSe051Tag11 = 0x4b;

  // se05x_enums.h:506-533. Note the applet-version caveat in se05x_ftr.h: on
  // applets older than 1.2 the "curve id" is a 32-bit value in the 0x7E000000
  // namespace instead of these one-byte ids. ReadECCurveList is the only way to
  // find out which convention a given part uses.
  constexpr uint8_t kSe051CurveNistP256 = 0x03;
  constexpr uint8_t kSe051CurveSecp256k1 = 0x10;
  constexpr uint8_t kSe051CurveEd25519 = 0x40;
  constexpr uint8_t kSe051CurveMontDh25519 = 0x41;

  // se05x_enums.h:546-555, sent as TLV tag 2 in SetECCurveParam.
  constexpr uint8_t kSe051EcParamA = 0x01;
  constexpr uint8_t kSe051EcParamB = 0x02;
  constexpr uint8_t kSe051EcParamG = 0x04;
  constexpr uint8_t kSe051EcParamN = 0x08;
  constexpr uint8_t kSe051EcParamPrime = 0x10;

  // se05x_enums.h:325-337.
  constexpr uint8_t kSe051SignAlgoPlain = 0x09;
  constexpr uint8_t kSe051SignAlgoSha256 = 0x21;

  // sm_const.h:28-36, APPLET_NAME for SSS_HAVE_APPLET_SE05X_IOT (SE051 shares
  // this applet).
  constexpr size_t kSe051AidSize = 16;
  constexpr uint8_t kSe051Aid[kSe051AidSize] = {
      0xa0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00,
      0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00};

  // se05x_const.h: SE05X_MAX_BUF_SIZE_CMD/RSP is 1024 for applet >= 4.4
  // (SSS_HAVE_SE05X_VER_GTE_07_02), which is the SE051 line. Commands built
  // here stay under a short APDU's 255-byte Lc; larger payloads are refused
  // rather than silently switching to an encoding no card has confirmed.
  constexpr size_t kSe051MaxData = 255;
  constexpr size_t kSe051MaxApdu = kSe051MaxData + 8;

  // TLV writer over a caller buffer: 1-byte tag, short-form length, value.
  // se05x_tlv.c tlvSet_u8buf uses exactly this length rule (below 0x80 one
  // byte, 0x81 + 1 byte up to 0xFF, 0x82 + 2 bytes above).
  class Se051TlvBuilder
  {
  public:
    Se051TlvBuilder(uint8_t *buffer, size_t capacity);

    bool tag_u8(uint8_t tag, uint8_t value);
    bool tag_u16(uint8_t tag, uint16_t value);
    bool tag_u32(uint8_t tag, uint32_t value);
    bool tag_bytes(uint8_t tag, const uint8_t *value, size_t size);

    size_t size() const { return size_; }
    bool ok() const { return ok_; }

  private:
    bool reserve(uint8_t tag, size_t size);

    uint8_t *buffer_;
    size_t capacity_;
    size_t size_;
    bool ok_;
  };

  // Every builder writes a complete command APDU (header, Lc, data and, for the
  // cases that expect a response, the Le byte). `*out_size` is only written on
  // success.
  bool se051_apdu_get_version(uint8_t *out, size_t capacity, size_t *out_size);
  bool se051_apdu_read_curve_list(uint8_t *out, size_t capacity,
                                  size_t *out_size);
  bool se051_apdu_create_ec_curve(uint8_t curve_id, uint8_t *out,
                                  size_t capacity, size_t *out_size);
  bool se051_apdu_set_ec_curve_param(uint8_t curve_id, uint8_t param,
                                     const uint8_t *value, size_t value_size,
                                     uint8_t *out, size_t capacity,
                                     size_t *out_size);
  // ECDSA (P-256, secp256k1) and EdDSA (Ed25519) share this command; the
  // algorithm byte says which. `digest` is passed as-is, so use
  // kSe051SignAlgoPlain when the caller already hashed.
  bool se051_apdu_sign(uint32_t object_id, uint8_t algorithm,
                       const uint8_t *input, size_t input_size, uint8_t *out,
                       size_t capacity, size_t *out_size);
  bool se051_apdu_ecdh(uint32_t object_id, const uint8_t *peer_public,
                       size_t peer_public_size, uint8_t *out, size_t capacity,
                       size_t *out_size);
  // The in-card HMAC the BIP32 derivation design needs: HMAC over `data` with
  // the key living in the object. Nothing leaves the card.
  bool se051_apdu_hmac(uint32_t object_id, uint8_t mac_operation,
                       const uint8_t *data, size_t data_size, uint8_t *out,
                       size_t capacity, size_t *out_size);
  bool se051_apdu_session_create(uint32_t auth_object_id, uint8_t *out,
                                 size_t capacity, size_t *out_size);
  bool se051_apdu_session_policy(const uint8_t *policy, size_t policy_size,
                                 uint8_t *out, size_t capacity,
                                 size_t *out_size);
  bool se051_apdu_verify_session_user_id(const uint8_t *user_id,
                                         size_t user_id_size, uint8_t *out,
                                         size_t capacity, size_t *out_size);
  bool se051_apdu_get_random(uint16_t size, uint8_t *out, size_t capacity,
                             size_t *out_size);

  // Response helpers. `response` includes the two status bytes; these split them
  // off and walk TLVs, refusing truncated or non-minimal encodings.
  bool se051_response_status(uint16_t *status, const uint8_t *response,
                             size_t response_size);
  bool se051_response_tlv(uint8_t tag, const uint8_t **value,
                          size_t *value_size, const uint8_t *response,
                          size_t response_size);
  // Curve ids present in a ReadECCurveList response (TLV tag 1, one byte each).
  bool se051_response_curve_list_contains(uint8_t curve_id, bool *present,
                                          const uint8_t *response,
                                          size_t response_size);

  // ---------------------------------------------------------------------------
  // Curve parameters
  // ---------------------------------------------------------------------------
  //
  // A part whose curve list does not already contain secp256k1 or P-256 needs
  // the five domain parameters installed before any key object can reference
  // them. The values below are transcribed from
  // hostlib/hostLib/inc/se05x_ecc_curves_values.h in plug-and-trust, which is
  // the same table the SDK's own Se05x_API_CreateCurve_* helpers send: prime,
  // a, b, G (uncompressed, 0x04 prefixed) and the order, big endian, in that
  // command order.
  //
  // run_se051_apdu_self_tests() re-derives these from src/EcdsaCurve.h and
  // compares them byte for byte. That check is the reason to trust them: a
  // transcription error would otherwise only show up as a card that accepts the
  // parameters and then produces signatures the firmware cannot verify.
  struct Se051CurveParams
  {
    uint8_t curve_id;
    const uint8_t *prime; // 32
    const uint8_t *a;     // 32
    const uint8_t *b;     // 32
    const uint8_t *g;     // 65, 0x04 || X || Y
    const uint8_t *order; // 32
  };

  // Returns nullptr for a curve this firmware does not provision.
  const Se051CurveParams *se051_curve_params(uint8_t curve_id);

  // ---------------------------------------------------------------------------
  // Drivers
  // ---------------------------------------------------------------------------
  //
  // The applet sits behind SCP03, so these take a "send one command, get one
  // response" callback instead of owning a transport: the caller wraps each
  // frame with scp03_wrap_command() and unwraps the reply. That keeps this file
  // free of channel state and makes the sequence testable on the host.
  //
  // Return value semantics are deliberately blunt: every command must answer
  // 0x9000. A partial curve is worse than no curve, because the next attempt
  // cannot tell how far the previous one got.
  using Se051Sender = bool (*)(void *context, const uint8_t *command,
                               size_t command_size, uint8_t *response,
                               size_t response_capacity, size_t *response_size);

  // CreateECCurve followed by the five SetECCurveParam commands. `status`
  // receives the first non-0x9000 status word, or 0x9000 on success.
  bool se051_install_curve(Se051Sender send, void *context, uint8_t curve_id,
                           uint16_t *status);

  // Reads the curve list and reports whether `curve_id` is provisioned. A card
  // that answers 0x6A88 or 0x6A80 to ReadECCurveList is reported as an error
  // rather than as "absent": those words can name any missing object, and
  // treating them as "no curves" is exactly the mistake Se051Provisioning was
  // written to avoid.
  bool se051_curve_present(Se051Sender send, void *context, uint8_t curve_id,
                           bool *present, uint16_t *status);

  // ---------------------------------------------------------------------------
  // PIN session
  // ---------------------------------------------------------------------------
  //
  // The in-card BIP32 design keeps c_par in a P1_HMAC_KEY object bound to a
  // UserID, so every HMAC needs an authenticated session. This tracks the
  // sequence the SDK uses (CreateSession -> policy -> VerifySessionUserID) and
  // the ISO 7816-4 retry counter: 0x63Cx means "x attempts left", and reaching
  // zero locks the slot until the card is reset by an administrator.
  //
  // The applet's own status words are not published; only the ISO 7816-4
  // 0x63Cx convention is, so that is the only one interpreted here.
  enum class Se051PinState : uint8_t
  {
    Idle = 0,
    SessionCreated,
    Authenticated,
    Locked,
  };

  struct Se051PinSession
  {
    Se051PinState state;
    uint8_t attempts_left; // 0xFF until the card reports a counter
    uint16_t last_status;
  };

  void se051_pin_reset(Se051PinSession *session);

  // Creates the session and applies `policy` (8 bytes as the SDK expects). The
  // session is not usable for signing until se051_pin_verify() succeeds.
  bool se051_pin_begin(Se051Sender send, void *context, uint32_t auth_object_id,
                       const uint8_t *policy, size_t policy_size,
                       Se051PinSession *session);

  // VerifySessionUserID with a PIN-derived user id. A 0x63Cx answer decrements
  // the reported retry counter and locks the session at zero; any other
  // non-0x9000 answer is reported as a failure without touching the counter,
  // because a malformed command must not burn a user's attempt.
  bool se051_pin_verify(Se051Sender send, void *context, const uint8_t *user_id,
                        size_t user_id_size, Se051PinSession *session);

  // True only for a session that the card has authenticated and that is not
  // locked. This is the condition the custody gate needs.
  bool se051_pin_authenticated(const Se051PinSession *session);

  // Runs one HMAC inside an authenticated session.
  bool se051_pin_hmac(Se051Sender send, void *context,
                      const Se051PinSession *session, uint32_t object_id,
                      uint8_t mac_operation, const uint8_t *data,
                      size_t data_size, uint8_t *out, size_t capacity,
                      size_t *out_size);

  // Pins the exact frames and the TLV length rules. The expected bytes are
  // derived from the header/P1/P2/tag values above, so a mistranscribed
  // constant fails here instead of at provisioning time on a real card.
  bool run_se051_apdu_self_tests();

} // namespace hexwallet

#endif
