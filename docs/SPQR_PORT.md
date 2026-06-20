# SPQR port plan (Sparse Post-Quantum Ratchet)

Porting Signal's **SparsePostQuantumRatchet** to pure C# so Wingnal can decrypt/encrypt modern
Signal messages. Required because new linked devices must declare the `spqr` capability, and the peer
then mixes SPQR output into every message's key schedule — a classic Double Ratchet gets "bad MAC".

- **Source:** `github.com/signalapp/SparsePostQuantumRatchet`, **tag v1.5.1** (the version libsignal
  pins in its root `Cargo.toml`). Reference checked out under `_spqrref/` (scratch; re-fetch from the
  tag if missing). Rust is formally verified (hax_lib/F* annotations) — ignore those attributes.
- **libsignal integration:** `rust/protocol/src/ratchet.rs` calls `spqr::initial_state(Params{
  direction, version:V1, min_version:V1, auth_key, chain_params})` at session init (A2B for initiator,
  B2A for recipient), and per message the SPQR `SecretOutput` (`None` / `Send(secret)` / `Recv(secret)`)
  is mixed into the sending/receiving chain before deriving message keys. `spqr_chain_params(self_connection)`
  builds ChainParams. The `pq_ratchet` bytes ride in `SignalMessage.pq_ratchet` (field 5) and prekey msgs.
- **Target namespace:** `Wingnal.Protocol.Spqr`.

## Module dependency order (bottom-up) and status

1. **Gf16** — GF(2^16), poly 0x1100b. ✅ DONE (`Spqr/Gf16.cs`, Gf16Tests: field axioms + all-inverses).
2. **encoding/polynomial.rs** — systematic fountain code over GF16. ✅ DONE (`Spqr/Polynomial.cs`:
   Poly(interpolate/evaluate), Encoder.ChunkAt, Decoder; PolynomialTests round-trips systematic +
   erasure at 1184/1088B). KEY: msg→16 polys round-robin by 2-byte symbol; chunk idx = all 16 polys at
   x=idx (32B); first ⌈M/16⌉ chunks are the message (systematic), rest are parity. NOTE: state
   serialization (into_pb/from_pb PolynomialEncoder) deferred to the proto layer.
3. **encoding/round_robin.rs** — TEST-ONLY stub (#![cfg(test)]), NOT ported. encoding.rs API
   (Chunk{index:u16,data:[u8;32]}, Encoder/Decoder traits) folded into Polynomial.cs. ✅ N/A.
4. **incremental_mlkem768.rs** — incremental/chunked ML-KEM-768 over libcrux's
   `mlkem768::incremental` API. PENDING — HARDEST/LINCHPIN. Splits keygen into pk1=hdr(64B) +
   pk2=ek(1152B), and encaps into encaps1(hdr)->ct1(960B)+state(2080B)+ss(32) and encaps2(ek,state)->
   ct2(128B); decaps(dk(2400B),ct1,ct2)->ss. Must be BYTE-EXACT with libcrux (incl. issue-1275
   endianness quirk in serialized state). Likely needs porting FIPS-203 ML-KEM-768 K-PKE from
   cryspen/libcrux. BC has ml_kem_768 but NOT the incremental split. RISK: feasibility of byte-exact match.
   **ANALYSIS (key for porting):** the "incremental" API is just standard FIPS-203 ML-KEM-768 with the
   ek and ciphertext SPLIT so they can be chunked:
   - keygen: pk1/header(64B) = rho(32) || H(ek)(32); pk2/ek(1152B) = ByteEncode12(t_hat). dk(2400B) =
     standard ML-KEM-768 dk = dkPke(1152)||ek(1184)||H(ek)(32)||z(32).
   - encaps1(hdr): m random; (K,r)=G(m||H(ek)) [H(ek) from hdr]; gen A from rho; sample r_hat,e1,e2;
     u = Compress_du=10(A^T r + e1) = ct1(960B = 3*320); ss = K (returned now); state = (r_hat, e2, m).
   - encaps2(ek, state): v = Compress_dv=4(t_hat·r + e2 + Decompress_1(m)) = ct2(128B). state is LOCAL
     (never transmitted) so we can use OUR OWN representation — the libcrux issue-1275 endianness quirk
     is irrelevant to interop.
   - decaps(dk,ct1,ct2): standard ML-KEM-768 decaps on ct=ct1||ct2.
   INTEROP-CRITICAL bytes (all standard FIPS-203, so cross-impl compatible): header=rho||H(ek),
   ek=ByteEncode12(t_hat), ct1=compress10(u), ct2=compress4(v), ss=32. CONFIRM hdr byte order
   (rho||H(ek)) against cryspen/libcrux incremental source before relying on it.
   REUSE: same ring q=3329 as our round-3 Kyber-1024 (Kyber1024.cs) — NTT/zetas/montgomery/barrett/
   basemul/cbd-eta2 are identical; differences are k=3, du=10/dv=4 compression, and FIPS-203 hashing
   (keygen G(d||k); encaps (K,r)=G(m||H(ek)); implicit reject J(z||c); NO final KDF unlike round-3).
   VALIDATE: FIPS-203 ML-KEM-768 NIST KAT (deterministic) + end-to-end vs captured messages.
   **SCOPE-REDUCER:** BouncyCastle 2.5.1 has MLKemParameters.ml_kem_768 (standard FIPS-203). For the
   RECEIVING side we can likely reuse BC: keygen via BC (then header=rho||SHA3-256(ek), ek=BCek[..1152]),
   and decaps by reassembling ct=ct1(960)||ct2(128)=1088 (standard ct size) and calling BC decaps with
   our dk. Only the SENDING side's encaps1/encaps2 SPLIT (compute u=ct1 from header before ek arrives,
   then v=ct2) needs a from-scratch K-PKE encaps — and only if the protocol requires emitting ct1 before
   the peer's ek is fully received. CHECK lib.rs send/recv flow to confirm which ML-KEM ops the RECEIVE
   path actually invokes (we are B2A/recipient for the captured messages) before deciding how much to port.
5. **kdf.rs** + **authenticator.rs** — HKDF-SHA256 + HMAC. ✅ DONE (`Spqr/Authenticator.cs` via
   CryptoPrimitives; AuthenticatorTests). util.compare -> FixedTimeEquals. kdf -> CryptoPrimitives.Hkdf.
6. **chain.rs** (706 lines) — keyed chain / ChainParams. ✅ DONE (`Spqr/Chain.cs`: Direction,
   ChainParams[maxJump=25000,maxOoo=2000], KeyHistory(OOO+gc/trim), ChainEpochDirection(HKDF hash
   chain), Chain[new/AddEpoch/SendKey/RecvKey]; ChainTests: A2B==B2A, out-of-order, add-epoch). Info
   strings exact incl. "Chain  Start" (two spaces). Serialization (into_pb/from_pb) deferred to proto.
7. **v1/chunked/** (states, send_ct, send_ek) — the chunked SCKA state machine. ✅ DONE
   (`Spqr/SckaUnchunked.cs` = 9 crypto states; `Spqr/SckaChunked.cs` = 11 chunked states + `SckaStates`
   Send/Recv machine + message/payload types). In-memory object form (serialize.rs deferred).
8. **proto/pq_ratchet.rs** + **serialize.rs** — prost protobuf for STATE. ⏸ DEFERRED (not needed while
   sessions are in-memory; required only for durable session persistence). NOTE the WIRE message format
   (V1Msg / `pq_ratchet` bytes) is NOT protobuf — it is a custom compact format already implemented in
   `SpqrRatchet` (`[ver=1][varint epoch][varint index][type:1][varint chunkIdx‖32B]`), and IS done +
   interop-correct (it's MAC'd and a real message decrypted).
9. **lib.rs** top-level API: ✅ DONE (`Spqr/SpqrRatchet.cs`: InitialState/Send/Recv, Params, Version,
   Direction, version-negotiation guard, custom wire (de)serialization).
10. **Integration**: ✅ DONE & VALIDATED. `SessionState.Spqr` (in-memory `SpqrRatchet`);
    `RatchetingSession` inits A2B(Alice)/B2A(Bob) from the PQXDH `pqr_key`; `SignalMessage` carries
    `pq_ratchet` field 5 (already MAC'd via raw-bytes MAC); `ChainKey.DeriveMessageKeys(seed, pqrSalt)`
    mixes the SPQR key as the WhisperMessageKeys HKDF **salt** (NOT root/chain); `ReceiverChain` caches
    message-key SEEDS so out-of-order messages get their own salt. A real captured PreKeySignalMessage
    decrypts to "Test". (Captured-envelope decrypt harness: `CapturedEnvelopeDecryptTests` [Live] — some
    stale pre-re-link captures still fail with bad MAC; that's mismatched prekey material, not a bug.)

## Resume status (updated)

- **Full reference re-fetched:** `_spqrref/` now holds the COMPLETE v1.5.1 tree (the old partial checkout
  was missing `v1/chunked/*`, `v1/unchunked/*`, `proto/pq_ratchet.{proto,rs}`). v1/chunked is what lib.rs
  uses (`v1::chunked::states`). unchunked is the inner per-byte logic the chunked layer wraps.
- **Module 4 (incremental ML-KEM-768): ✅ DONE & KAT-validated.** `Spqr/MlKem768.cs` — standard FIPS-203
  ML-KEM-768 (k=3, du=10/dv=4, G(d‖k=3) keygen, (K,r)=G(m‖H(ek)) encaps, implicit reject J(z‖c)=SHAKE256,
  NO final KDF) + the incremental split (Generate→hdr/ek(pk2)/dk; Encaps1(hdr,m)→ct1/es/ss; Encaps2(pk2,es)
  →ct2; Decaps(dk,ct1,ct2)→ss). Reuses round-3 Kyber ring arith; matrix A[i][j]=XOF(rho,j,i) keygen
  (transposed:false) / XOF(rho,i,j) encrypt (transposed:true) — SAME convention as round-3 (the "FIPS
  swapped the index" claim is a MYTH; pq-crystals `standard` branch gen_a uses (j,i), gen_at (i,j)).
  `es` (encaps state) is LOCAL → our own int16-LE format. Validated `MlKem768Tests` against C2SP/CCTV
  ML-KEM-768.txt vector: Encaps/Decaps/incremental-split byte-exact (SHA256(c) + K match). NOTE: that
  CCTV vector is FIPS-203 **IPD** (G(d) with no rank byte); the keygen rank byte (final FIPS-203, matches
  libcrux) is LOCAL-ONLY/interop-irrelevant (keypairs are generated locally, only ek/ct cross the wire),
  so keygen is validated by self-consistency + dk-structure, encaps/decaps by the vector (ek/dk loaded
  directly from `MlKem768IpdVector`). 50 offline tests green.

## INTEGRATION MODEL (confirmed from libsignal v0.96.1, pins SPQR v1.5.1) — read before phase 10

- **PQXDH HKDF bug FIXED:** `RatchetingSession.DeriveKeys` used info `"WhisperText"` + 64B for BOTH X3DH
  and PQXDH. PQXDH must use info **`"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024"`** + **96B** =
  root[32]‖chain[32]‖**pqr_key[32]**. The pqr_key is the SPQR **auth_key**. This wrong label corrupted
  root+chain keys → the real cause of "bad MAC" (independent of SPQR). Now stored in
  `SessionState.SpqrAuthKey`; serialized SPQR state in `SessionState.PqRatchetState`. Secret-input order
  (0xFF*32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ [DH4] ‖ KEM_ss) already matched libsignal pqxdh.rs.
- **SecretOutput mixing:** the SPQR per-message `key` (Option<32B>) is used ONLY as the **HKDF salt** of
  the per-message `WhisperMessageKeys` derivation — NOT mixed into root/chain. i.e. `ChainKey.GetMessageKeys`
  must become `derive(IKM=HMAC(chainKey,0x01), salt=pqr_key, info="WhisperMessageKeys", 80)`. salt=null
  when SPQR key absent (classic). Root→chain (`WhisperRatchet`) is untouched.
- **Wire:** `pq_ratchet` = SignalMessage **field 5** and IS covered by the MAC (libsignal MACs the raw
  serialized bytes incl. field 5; our `SignalMessage.VerifyMac` already MACs raw `_serialized[..-8]`, so
  field 5 is covered — just need to PARSE field 5 out and ROUND-TRIP it when we send). MAC = HMAC-SHA256
  over senderIK(33)‖recvIK(33)‖(verbyte‖proto), truncated 8B (we already do this).
- **First message HAS a real salt:** SPQR `Chain` is seeded from auth_key at construction (epoch 0 exists);
  `send_key(0)`→index 1 + real key, so the first PreKeySignalMessage's salt is non-None. (The
  `msg_key_epoch==0 && index==0` empty-key case never fires for V1 since sent indices are ≥1.) So the full
  SPQR recv path (parse V1Msg → states.recv → chain.recv_key(epoch-1,index)) is needed even for msg 1.
- **chain_params:** max_jump=25000, max_ooo=2000 (non-self session).
- **A2B = initiator/Alice, B2A = recipient/Bob.** We are **B2A** for the captured phone messages (phone
  initiated). B2A init → `NoHeaderReceived` (send_ct role first epoch).
- **OOO caveat:** SPQR salt is per-message, so skipped/out-of-order message keys must be cached as the
  message-key SEED (HMAC(chainKey,0x01)) + counter and salted lazily at arrival (libsignal
  MessageKeyGenerator), NOT pre-derived. Refactor `ReceiverChain` cache accordingly (stage after in-order
  works).
- **State persistence:** libsignal stores serialized SPQR state in SessionStructure.pq_ratchet_state
  field 15; recv commits new SPQR state ONLY after MAC+decrypt succeed. For our captured-PreKeyMessage
  decryption, in-memory state per session is enough (each PreKeySignalMessage re-establishes).

## Validation strategy

- Per-module unit tests (field axioms, polynomial round-trips, ML-KEM-768 KAT, encode/decode round-trips).
- **End-to-end against real captured messages:** the phone's PreKeySignalMessages are saved as
  `%LOCALAPPDATA%\Packages\cdb9e5d5-..._cnsc1k9bd01st\LocalCache\Local\Wingnal\failed-envelope-*.bin`
  and keep redelivering (ChatReceiver doesn't ack on failure). `LiveChatConnectTests` [Category=Live]
  decrypts them; success = "bad MAC" disappears and we surface the text. This is the real proof.

## Key facts learned

- `SignalMessage.pq_ratchet` = field 5, `addresses` = field 6 (libsignal wire.proto). Our ProtoReader
  now skips unknown length-delimited fields correctly (fixed `_pos += ReadVarint()` eval-order bug).
- KEM ciphertext on the wire is `0x08 || raw` (Kyber-1024 type byte); SPQR uses ML-KEM-768 internally.
- Chat socket auth = `Authorization: Basic {aci.deviceId:password}` header (NOT query params).
