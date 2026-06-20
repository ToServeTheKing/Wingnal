# Shortcuts & Tech Debt

A running list of pragmatic shortcuts, hacks, and not-yet-proper-design decisions taken to keep the
MVP moving. These are deliberate and known — revisit before this is anything more than a prototype.
Newest entries near the top of each section. Date format: YYYY-MM-DD.

## Groups v2 build (in progress, 2026-06-16)

Executing the docs/GROUPS.md plan A→H. Done so far (each gated by byte-exact libsignal vectors):
- **Phase A** — Sender Key persistence: `SenderKeyRecord.Serialize/Deserialize` + `SqliteSenderKeyStore`
  (DPAPI). Test: `SenderKeyPersistenceTests` (chain + skipped-key cache survive restart).
- **Phase B** — Ristretto255 hand-port (BC 2.5.1 has no Ristretto): `Wingnal.Protocol/ZkGroup/Curve/`
  `Fe` (field over BC `X25519Field`; `PowP58` = ref10 pow22523 chain, since BC `PowPm5d8` is internal),
  `Ristretto255` (RFC 9496), `Scalar25519` (mod ℓ, BigInteger). SQRT_M1 is COMPUTED (p≡5 mod8 ⇒
  2·(2^((p-5)/8))²), not transcribed. Tests: `Ristretto255VectorTests` (RFC 9496 App-A) + `FeArithmeticTests`
  (fuzz vs BigInteger). SHORTCUT: scalar/point ops are NOT constant-time yet (BigInteger scalar,
  data-dependent double-and-add) — fine for client-side proofs, harden later.
- **Phase C** — poksho: `Wingnal.Protocol/ZkGroup/Poksho/` `ShoHmacSha256` (stateful HMAC sponge) +
  `Statement` (Schnorr proof for linear relations). Tests reproduce poksho's own SHO + complex-statement
  proof vectors byte-for-byte. Reference fetched via `gh api .../contents/... | base64 -d` (WebFetch
  summarizes — unsuitable for verbatim crypto source).
- **Phase D1** — `Wingnal.Protocol/ZkGroup/GroupSecretParams`: master-key → group_id + blob_key SHO
  derivation + AES-256-GCM-SIV blob encrypt/decrypt-with-padding (BC `GcmSivBlockCipher`). Gated by
  zkgroup's `test_encrypt_with_padding` vectors. Unblocks group-id routing (G1) + title/avatar decryption.
- **Phase D2 PART 1 DONE — the member-hiding ciphertext layer** (byte-exact vs libsignal vectors):
  - `ZkGroup/Curve/Lizard.cs` — Lizard 16-byte↔Ristretto encode/decode (curve25519-dalek-**signal** fork,
    NOT RFC 9496). Encode reuses the existing single-Elligator `ElligatorRistrettoFlavor` (renamed from
    `MapToPoint`, now also exposed as `Ristretto255.FromSingleElligatorBytes` = `get_point_single_elligator`).
    Decode = full Elligator inverse via the Jacobi quartic (`Ristretto255.ElligatorInverse` +
    `ToJacobiQuarticRistretto`). Lizard constants COMPUTED from `Fe` (SQRT_ID/DP1_OVER_DM1/MDOUBLE_/MIDOUBLE_/
    MINVSQRT_ONE_PLUS_D per the dalek lizard_constants test). Gate: `LizardTests` — 3 fork encode vectors +
    independent decode of the pinned points + 50× round-trip.
  - `ZkGroup/ZkCredential/AttributeEncryption.cs` — zkcredential `attributes` (Chase-Perrin-Zaverucha §4.1):
    `AttributeKeyPair` (a1,a2,A), `AttributeCiphertext` (E_A1=a1·M1, E_A2=a2·E_A1+M2; 64-byte ser),
    `DecryptToSecondPoint`. Added `Ristretto255.Negate`.
  - `ZkGroup/UidEncryption.cs` (`UidStruct`/SystemParams/`ServiceId`) + `ProfileKeyEncryption.cs`
    (`ProfileKeyStruct`/SystemParams; decrypt = `decode_253_bits` × 8 sign-bit variants). SystemParams are
    GENERATED via SHO (no transcribed point constants) and gated against the hardcoded 64-byte blobs.
    `Ciphertexts.cs` = `UuidCiphertext`/`ProfileKeyCiphertext` (reserved 0x00 ‖ 64 = 65B).
  - `GroupSecretParams.cs` extended: derives `UidKeyPair` + `ProfileKeyKeyPair` from the same SHO chain
    (group_id→blob_key→uid_kp→profile_kp), `EncryptServiceId`/`DecryptServiceId`/Encrypt/DecryptProfileKey,
    `PublicParamsSerialized` (97B). **This unblocks decrypting group rosters (Phase E read).**
  - Gates: `LizardTests`, `AttributeEncryptionTests` (uid + profile ciphertext vectors byte-for-byte,
    SystemParams==hardcoded, ACI/PNI + profile-key round-trips), `GroupSecretParamsTests` (member enc round-trip).
    163 offline tests green; WinUI app builds (x64).
- **Phase D2 PART 2 DONE — the AuthCredentialWithPni credential/presentation system** (byte-exact components):
  - `ZkGroup/Poksho/ShoSha256.cs` — the "innerpad" SHA-256 SHO (sibling of ShoHmacSha256). Gate: poksho's own
    ShoSha256 vector. Added `GetScalar`/`GetPoint` to ShoHmacSha256.
  - `ZkGroup/ZkCredential/CredentialSystem.cs` — the algebraic-MAC credential (Chase-Perrin-Zaverucha §3.1):
    `CredentialSystem.SystemParams` (13 generators via ShoSha256, **gated vs the 416-byte hardcoded hex** —
    this also pins ShoSha256.GetPoint), `Credential` (t,U,V), `CredentialPrivateKey` (w,wprime,W,x0,x1,y[7] +
    `CredentialCore` MAC), `CredentialPublicKey` (C_W, I[6]; `IFor(numAttrs)=I[numAttrs-2]`), `CredentialKeyPair`.
  - `ZkGroup/ZkCredential/CredentialProofs.cs` (`IssuanceProofBuilder` issue/verify) + `PresentationProof.cs`
    (`PresentationProofBuilder.Present` / `PresentationProofVerifier.Verify`) — both build a poksho `Statement`
    and reuse the byte-exact Schnorr engine. PresentationProof bincode ser = Cx0‖Cx1‖Cv‖u64le(n)‖Cy‖u64le(len)‖proof.
  - `ZkGroup/AuthCredentialWithPni.cs` — label `20240222_Signal_AuthCredentialZkc`; `Issue`/`Receive`/`Present`/
    `VerifyPresentation`. Presentation wire = version(3)‖PresentationProof‖aciCt(64)‖pniCt(64)‖u64le(redemption).
  - Gate: `AuthCredentialTests` — ShoSha256 vector, credential SystemParams==hardcoded, full
    issue→receive→present→verify round-trip (libsignal's zkc.rs test, fixed seeds) + ciphertext-consistency.
    167 offline tests green; WinUI app builds (x64).
  - RESIDUAL (live-only): the exact AUTH-presentation wire bytes aren't pinned to a libsignal hex vector (every
    *component* is byte-pinned — poksho proof, ciphertexts, SystemParams, MAC, bincode layout matches the Rust
    struct order — so the wire format should match; final proof is a 200 from storage.signal.org in Phase E).
    `ServerPublicParams` parsing (to extract generic_credential_public_key from Signal's real params) is NOT
    yet done — needed in Phase E to receive the real AuthCredential.
- **Phase G1 DONE (receive-side core) — receive-only group messages**:
  - `Wingnal.Service/Messaging/GroupMessageProcessor.cs` — `ProcessDistribution` (install a peer's SKDM),
    `DecryptGroupMessage` (SenderKeyMessage → padded Content), `GroupIdHex(masterKey)` (=GroupSecretParams
    group-id, lowercase hex) for routing. No zkgroup credentials needed to RECEIVE.
  - `MessageDecryptor` wiring (guarded by an optional `ISenderKeyStore` — 1:1 path unchanged when absent):
    sealed-sender inner type 7 (SENDERKEY) → group decrypt → strip padding → Content; any decrypted Content
    carrying `senderKeyDistributionMessage` → install it; `DecryptedMessage.GroupId` set from
    `DataMessage.groupV2.masterKey`.
  - Wired live: `ChatReceiver` takes an `ISenderKeyStore`; `ChatPage` passes a `SqliteSenderKeyStore`
    (`_senderKeys`, %LOCALAPPDATA%\Wingnal\senderkeys.db).
  - Gate: `GroupReceiveTests` (offline loopback: distribute → decrypt → group-id routing) + group-id
    derivation match. 169 offline tests green; app builds (x64).
  - REMAINING for full G1 visibility (Phase H territory): `ChatPage.OnMessage` does NOT yet route by
    `GroupId` — a group message currently lands in the *sender's* 1:1 thread (visible but not grouped); no
    group conversation/roster UI. Live-UNTESTED (headless): the real sealed-sender SENDERKEY socket path.
- **Phase E PARTIAL DONE — group storage-service read path + API client**:
  - `Wingnal.Service/Protos/Groups.proto` (vendored from Signal-Android `lib/.../protowire/Groups.proto`,
    `package signal`, `csharp_namespace = Wingnal.Service.Protos.Groups`): Group/Member/AccessControl/
    GroupChange/GroupAttributeBlob/GroupResponse/GroupChanges etc.
  - `Wingnal.Service/Groups/GroupStateCodec.cs` + `DecryptedGroup.cs` — decrypts a fetched `Group` into a
    plaintext model: member service ids via `GroupSecretParams.DecryptServiceId` (UuidCiphertext), title/
    description via the GCM-SIV attribute blob → `GroupAttributeBlob`. Gate: `GroupStateCodecTests` (full
    round-trip — encrypt members+title with a derived GroupSecretParams, build a Group proto, decode, assert
    roster/roles/title). Offline.
  - `Wingnal.Service/Groups/GroupsApiClient.cs` — `storage.signal.org` (`SignalServiceConfig.StorageUrl`,
    same `SignalTrust` pin). GET `/v2/groups/` → GroupResponse.Group; GET `/v2/groups/logs/{rev}` →
    GroupChanges; PATCH `/v2/groups/` → GroupChangeResponse. Auth = `Basic base64(hex(GroupPublicParams):
    hex(presentation))` (per Signal-Android `GroupsV2AuthorizationString`). Gate: `AuthHeader` format test.
    LIVE-UNTESTED (headless): the actual storage round-trip.
  - 171 offline tests green; app builds (x64).
- **Phase E REMAINING (live flow):** `ServerPublicParams` parsing (extract `generic_credential_public_key`
  + `sig_public_key`) — needs Signal's PUBLISHED production ServerPublicParams constant (data, not derivable;
  fetch from Signal-Android/Desktop config like the CA pem) — and the AuthCredentialWithPni FETCH from the
  chat server (GET the credential response, `AuthCredentialWithPni.Receive`). Then wire
  `AuthCredentialWithPni.Present(group)` → `GroupsApiClient.GetGroupAsync` → `GroupStateCodec.Decode`.
- **Phase F PARTIAL DONE — membership model + GroupChange application** (offline core):
  - `Wingnal.Service/Groups/GroupChangeApplier.cs` — applies a `GroupChange.Actions` delta to a
    `DecryptedGroup` (decrypting member/title fields): add/delete/modify-role members, promote-pending,
    modify title/description, revision bump. (Pending/requesting/banned/access-control/timer actions are
    recognised + skipped for now.) Gate: `GroupChangeTests.Apply_*`.
  - `Wingnal.Service/Groups/GroupStore.cs` (+`StoredGroup`) — SQLite (%LOCALAPPDATA%\Wingnal\groups.db),
    keyed by hex group id; master key + title + roster JSON encrypted at rest via `LocalCipher`. Gate:
    `GroupChangeTests.GroupStore_PersistsAndReloads`.
  - `Wingnal.Protocol/ZkGroup/Poksho/PokshoSignature.cs` — poksho Schnorr signature (`public_key=private_key·G`,
    reuses the Statement engine) + `Wingnal.Service/Groups/GroupSignatureVerifier.cs` (verify a GroupChange's
    server signature over its actions bytes). Gate: `PokshoSignatureTests` (poksho signature vector byte-exact).
    174 offline tests green; app builds (x64).
- **Phase F REMAINING (live):** the server's sig PUBLIC key (= `ServerPublicParams.sig_public_key`, the same
  production-constant blocker as Phase E) to verify REAL changes; the incremental `GET /v2/groups/logs`
  reconcile loop (apply changes from stored revision → latest); pending/requesting/banned member modelling.
- **Phase G2 DONE (send crypto core)**: `Wingnal.Service/Messaging/GroupSendBuilder.cs` — `CreateDistribution`
  (our SKDM to send 1:1 to members) + `EncryptMessage(Content)` (the single group ciphertext, padded, that
  every member device gets). Also extracted `Wingnal.Service/Messaging/MessagePadding.cs` (Add/Strip; replaced
  the duplicated private padding in MessageSender + MessageDecryptor — still green). Gate:
  `GroupSendReceiveLoopbackTests` (offline 3-member: encrypt-once → 2 receivers + a late-joiner decrypt +
  group-id route). 175 offline tests green; app builds (x64).
- **Phase G2 REMAINING (live):** the fan-out/transport — for each member device, wrap the SenderKeyMessage as
  sealed-sender (type 7) via the existing `EncryptWithCertificate` and send (reuse `MessageSender`); send the
  SKDM (sealed 1:1) to members who lack our key; handle 409/410 device-set changes per member.
- **ServerPublicParams DONE** (the keystone that was blocking the live credential flow):
  `Wingnal.Protocol/ZkGroup/ServerPublicParams.cs` embeds Signal's PRODUCTION `ZKGROUP_SERVER_PUBLIC_PARAMS`
  base64 (from Signal-Android BuildConfig — the `AMhf5ywV…` prod value, NOT staging) and `Parse` extracts
  `sig_public_key` (bytes[129..161]) + `generic_credential_public_key` (bytes[417..641], = C_W‖I[6]). Offsets
  computed from the struct layout (1 + 6×64 + 32 sig + 224 generic + 32 endorsement = 673 = SERVER_PUBLIC_PARAMS_LEN).
  Gate: `ServerPublicParamsTests` (decodes to 673; parses into valid canonical Ristretto points — a wrong
  offset would fail Decode; also cross-validates `CredentialPublicKey.Deserialize` against REAL production data).
  Also: `AuthCredentialWithPni.IssueResponse`/`ReceiveResponse` + `IssuanceProof.Serialize/Deserialize` (the
  `version(3)‖IssuanceProof` wire form); `ReceiveResponse` defaults to `ServerPublicParams.Production`. Gate:
  `AuthCredentialResponse_Serialization_RoundTrips`. 178 offline tests green; app builds.
- **OVERALL GroupsV2: ALL crypto/protocol layers DONE + gated** — D2 crypto, G1 receive, E decode + API
  client, F apply + store + sig-verify, G2 encrypt-once, ServerPublicParams + credential-response wire.
  **Remaining is live-network + UI only:** (1) the chat-server endpoints to FETCH the AuthCredentialWithPni
  response (then `ReceiveResponse`) and to drive group GET/PATCH round-trips + sealed-sender group fan-out +
  409/410 + `/logs` reconcile; (2) **Phase H** group UI (group conversation list + roster + new-group/add/leave
  + route ChatPage.OnMessage by `GroupId` so received group msgs land in a group thread, not the sender's 1:1).
  `GroupSignatureVerifier` can now use `ServerPublicParams.Production.SigPublicKey` for real changes.
  DONE this session: `SqliteSenderKeyStore.Clear()` + `GroupStore.Clear()` are now wired into the unlink wipe
  (`SettingsPage.OnUnlinkClick`).
- NOTE: Lizard/Ristretto scalar+point ops remain non-constant-time (existing shortcut); decode uses
  data-dependent branching — fine for client-side group decryption.

## Display / sync fixes (2026-06-16)

- ~~Thread showed only the OLDEST messages (capped ~1/8/26)~~ (FIXED). `MessageStore.Recent` was
  `ORDER BY timestamp ASC LIMIT 200` → the oldest 200, so a long (imported) thread never showed recent
  messages. Now selects the NEWEST N (`DESC LIMIT 500`) and reverses for chronological display. Test:
  `MessageStoreTests.Recent_ReturnsNewestN_InChronologicalOrder`. (No infinite-scroll yet → messages
  older than the newest 500 in a thread aren't loaded; a follow-up if needed.)
- **Contacts re-sync on unknown sender** (2026-06-16). A message from a peer we have no name for now
  triggers a debounced (≤1/min) contacts re-sync (`ChatPage.MaybeResyncContacts` → `SendSyncRequests`
  CONTACTS), so a newly-added phone contact resolves to a name (the response refreshes all titles via
  OnSync→RefreshTitles). LIMIT: only resolves names for people saved in the phone's contacts; a pure ACI
  with no saved contact still shows the short id (no CDSI/profile-name fetch).
- **Receipts (✓/✓✓) + typing indicators** (2026-06-16). `Receipts` builds the sideband `Content`
  (DELIVERY/READ `ReceiptMessage`, START/STOP `TypingMessage`); `ChatReceiver` surfaces them via
  `onReceipt`/`onTyping`. On receiving a 1:1 message we send DELIVERY (or READ if the thread is open);
  opening a thread with unread messages sends READ; a peer's receipt advances our bubble to
  Delivered/Read (monotonic via `MessageItem.Rank`, so a late DELIVERED never downgrades a READ).
  Outbound typing is throttled to once/5s and STOPs on send; inbound shows a "<name> is typing…" pill
  that auto-clears after 6s. Offline-tested: the wire builders (`ReceiptsTests`). LIMITS: per-message
  Delivered/Read state is NOT persisted — it shows only while the thread stays open (a reopen resets
  bubbles to plain time); receipts are matched only for the currently-open peer; no "viewed" (view-once)
  receipts; no per-message read marker in the conversation list; the user's read-receipt privacy toggle
  isn't honored (we always send). LIVE-UNTESTED (headless): the round-trip over the socket.
- **Inline media: inbound attachments download + render** (2026-06-16). `MessageDecryptor` surfaces the
  first `AttachmentPointer` on `DecryptedMessage.Attachment`; `ChatPage.OnMessage` downloads+decrypts it
  to `%LOCALAPPDATA%\Wingnal\media\` via `AttachmentService.SaveAsync` (reuses `AttachmentDownloader` +
  the tested `AttachmentCipher`), persists the local path (`MessageStore.media` column, encrypted; idempotent
  ALTER migration), and the bubble shows the image inline (`MessageItem.ImageSource`) or the
  "📷/🎥/🎙/📎" placeholder for non-image/failed types. Offline-tested: pointer surfacing + file save
  (`AttachmentServiceTests`). LIVE-UNTESTED (headless): the CDN GET + image render. REMAINING: SENDING
  media (needs picker + CDN upload), reactions attached to their target bubble (still a separate line),
  history-imported media (`BackupImporter` imports text only), tap-to-open for non-image files.
- **Groups + remaining features still missing** (known, large). No group chats (needs Groups v2 — zkgroup
  + storage service + membership + sealed-sender fan-out; only the Sender Key crypto primitive exists,
  docs/GROUPS.md). Now done: inline media download/render, delivery/read receipts, typing indicators
  (see entries above). Still not implemented: SENDING media (picker + CDN upload), profile name/avatar
  fetch for non-contacts, calls, stories, edit/delete-for-everyone, view-once. Each is its own feature.

## Minimal-code audit (ponytail pass, 2026-06-16)

Collapsed custom code into BCL/shared helpers (all covered by existing byte-exact tests → still 113 green):
- ~6 hand-rolled UUID↔RFC-4122 byte reorders → .NET 8 `Guid.ToByteArray(bigEndian:true)` /
  `new Guid(span, bigEndian:true)` (SafetyNumber, BackupKey, SenderKey wire).
- 4 copies of "service-id binary → uuid string" → one `Wingnal.Service.ServiceIds.StringFromBinary`
  (MessageDecryptor, SyncProcessor, SealedSenderDecryptor, BackupImporter).
- 2 manual hex parsers → `Convert.FromHexString` (Ed25519Ct, TestHex).
- `DeviceNameCipher`'s private AES-CTR (+counter, ~30 lines) → the shared `CryptoPrimitives.AesCtr`.

DELIBERATE exceptions (NOT ponytail violations — keep as custom): the pure-.NET Signal protocol port is
the whole point of the project (no signal-cli / Rust FFI) and is security-vector-tested — the hand-written
protobuf codec in `Wingnal.Protocol` (intentionally avoids a protobuf-compiler dep there), the BigInteger
Ed25519 reference (kept for verify + as the constant-time cross-check oracle), and the ML-KEM/SPQR/ratchet
ports all stay. They're "custom" by design, not by oversight.

## Correctness / protocol risks (highest priority)

- ~~No identity-change detection (silent MITM)~~ (RESOLVED 2026-06-16). `IIdentityKeyStore.IsTrustedIdentity`
  added (trust-on-first-use: a *different* key for a known address is untrusted). `SessionBuilder` (both
  initiator bundle + responder prekey paths) throws `UntrustedIdentityException` before establishing, so a
  changed identity no longer silently proceeds. `SafetyNumber` (Wingnal.Protocol/Identity) computes the
  Signal-exact numeric fingerprint (version 2, 5200× SHA-512, 16-byte ACI stable id) — **validated
  byte-exact against libsignal's own vector** so it matches the official app. `ChatPage` surfaces a
  "safety number changed" dialog (warning + the number + Verify & approve) on both send and receive; approve
  = `SqliteSignalProtocolStore.ResetPeer(name)` (forget old identity + dead sessions → re-trust on next
  establish). Tests: SafetyNumberTests (vector/symmetry/diff), IdentityTrustTests.
  Proactive "view safety number" is also available (shield button in the thread header → read-only dialog).

## Security hardening (the "nervous-making" list)

- ~~Messages/contacts plaintext at rest~~ (RESOLVED 2026-06-16). `LocalCipher` (AES-256-GCM under a
  random per-install key, DPAPI-wrapped at `%LOCALAPPDATA%\Wingnal\local.key`) encrypts message **bodies**
  (MessageStore) and contact **names/numbers** (ContactsStore) at rest; peer ACIs + timestamps stay
  plaintext so the list/threads stay queryable/sortable. Legacy plaintext rows decrypt-through unchanged
  (no migration). Tests: LocalCipherTests (round-trip, non-determinism, legacy passthrough, on-disk
  ciphertext check). RESIDUAL: peer ACIs + message timing are still visible at rest (content + the
  ACI→name mapping are not) — full-DB encryption would need SQLCipher (native dep).
- ~~Sealed-sender certs not validated~~ (RESOLVED 2026-06-16). `SenderCertificateValidator` checks the
  trust root → server-cert → sender-cert signature chain + expiry against Signal's production trust roots;
  `SealedSenderDecryptor.Decrypt` rejects an invalid/expired/forged cert. Tests: round-trip-with-chain,
  reject-untrusted-root, reject-expired, reject-tamper.
- ~~EC/XEdDSA core is not constant-time~~ (RESOLVED 2026-06-16). XEdDSA **signing** now runs through
  `Ed25519Ct` — a constant-time fixed-base scalar multiply + ref10 constant-time scalar arithmetic mod L
  (`ScReduce`/`ScMulAdd`), built on BouncyCastle's vetted constant-time field `X25519Field`. Verify (no
  secret) stays on the BigInteger reference. Gated by cross-check: `Ed25519CtTests` confirm the CT
  primitives are byte-identical to the KAT-validated reference across 192 random inputs, and the XEdDSA
  vector + all signing-dependent tests pass — so signing is unchanged in output, just constant-time.
  GOTCHAs found during the port (documented so they don't recur): BC's `X25519Field.CMov` takes a FULL
  word mask (0/0xFFFFFFFF), not 0/1; chained `Add`/`Sub` need `Carry` before `Mul`; `Mul`/`Sqr` are not
  alias-safe (distinct output arrays); the `d` constant is computed from -121665/121666 (not hardcoded)
  to avoid transcription error.
- ~~Sends are unsealed (metadata leak)~~ (RESOLVED 2026-06-16, opportunistic). `MessageSender.TrySealedAsync`
  now sends sealed-sender when it can: it captures peers' profile keys from inbound DataMessages
  (`ProfileKeyStore`, encrypted at rest), derives their unidentified-access key
  (`UnidentifiedAccess.DeriveAccessKey`), fetches a delivery certificate (`GET /v1/certificate/delivery`,
  cached), re-wraps the already-built per-device ciphertexts as sealed envelopes
  (`SealedSenderDecryptor.EncryptWithCertificate`), and sends them WITHOUT auth + the UD-key header. The
  inner ciphertext is reused (ratchet advances once), and ANY missing prerequisite or failure falls back
  to the authenticated send — so it never regresses. Offline-tested: access-key derivation, encrypted
  ProfileKeyStore, sealed encrypt/decrypt-with-cert. LIVE-UNTESTED (can't headless-verify): the cert
  fetch + unauthenticated UD send. Metadata protection only kicks in for recipients whose profile key
  we've captured (i.e., after they've messaged us); others still send authenticated.

- ~~XEdDSA verify forced the Edwards sign bit to 0~~ (RESOLVED 2026-06-16, Step 7). `XEd25519.VerifySignature`
  forced A's sign bit to 0 and used the full `s`. Signal's curve25519 XEdDSA instead stashes A's natural
  sign bit in the high bit of `s` (signature[63]); the verifier must read it back, reconstruct A with that
  sign, and clear the bit before parsing `s`. The bug was latent (only the verify path on REAL peer
  prekeys exercised it — our own signer always emits sign-bit-0 keys, the case it accepted). It blocked
  outgoing sends (prekey-bundle signature verification). Fixed + KAT-tested vs libsignal's own vector
  (XEd25519VectorTests).

- ~~Declaring the `spqr` capability without implementing it~~ (RESOLVED 2026-06-16). SPQR (Sparse
  Post-Quantum Ratchet) is now fully implemented in `Wingnal.Protocol/Spqr/` (ML-KEM-768, SCKA state
  machine, Chain, Authenticator, lib API) and integrated into the ratchet/session cipher. Validated:
  a real captured phone PreKeySignalMessage now decrypts to plaintext ("Test") — bad MAC gone. Also
  fixed the PQXDH HKDF label bug (`WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024`, 96-byte output)
  that was the underlying cause of the bad MAC. See `docs/SPQR_PORT.md`.
- **SPQR state is in-memory only; no proto serialization yet** (2026-06-16). NOTE: the published
  **ML-KEM Braid** spec (signal.org/docs/specifications/mlkembraid) confirms our SPQR/SCKA port — KDF
  labels (PROTOCOL_INFO `Signal_PQCKA_V1_MLKEM768` + `:Authenticator Update` / `:SCKA Key` / `:ekheader`
  / `:ciphertext`), header = `ek_seed‖hek`, incremental ML-KEM-768, chunked erasure coding. The spec
  leaves wire format/state serialization implementation-defined (custom or protobuf) and does not
  specify DR integration, so our in-memory state + hand-rolled wire format are spec-compliant choices,
  not gaps. Persistence remains the only real follow-up here. `SessionState.Spqr` holds a
  live `SpqrRatchet` object (and `SckaStates`/`Chain`/`Authenticator` objects) rather than the
  prost-serialized `PqRatchetState`. Fine while sessions are in-memory (they already are — see "Sessions
  are in-memory only"), but durable session persistence needs `into_pb`/`from_pb` for the SPQR state
  (proto/pq_ratchet.proto). *Proper:* port the serialize.rs layer when adding the SQLite session store.
- **ML-KEM-768 keygen uses the final-FIPS-203 rank byte; KAT-validated only on encaps/decaps**
  (2026-06-16). `MlKem768.Generate` appends `k=3` in `G(d‖k)` (final FIPS-203, matches libcrux). The
  available C2SP KAT vector is FIPS-203 IPD (no rank byte), so keygen is validated by self-consistency +
  dk-structure while encaps/decaps (the interop-critical, IPD≡final ops) are KAT-validated byte-exact.
  The rank byte only affects the local seed→keypair map (never on the wire), so this is safe.
- ~~Device-name encryption unverified~~ (RESOLVED 2026-06-16). Matched against Signal-Android
  `DeviceNameCipher.kt`; the AES-CTR IV must be zero (not the syntheticIv). Round-trip tested.
- ~~QR scheme is a guess~~ (RESOLVED 2026-06-16). `sgnl://linkdevice?...` confirmed working — a real
  phone linked successfully.

## Key management / persistence

- **Registered prekeys stashed inside the account blob** (2026-06-16). `SignalAccount.AciPreKeys` /
  `PniPreKeys` (`RegisteredPreKeys`) carry the signed + last-resort kyber private material directly in
  `account.bin` instead of a real key store. *Proper:* a persistent `SignalProtocolStore` (SQLite),
  shared by linking and the session layer.
- ~~No persistent `SignalProtocolStore` for the app~~ (RESOLVED 2026-06-16). `SqliteSignalProtocolStore`
  implements all five store interfaces, persisting sessions + learned identities to SQLite with each blob
  DPAPI-protected at rest; identity/signed/kyber/one-time prekeys are still seeded from `account.bin`.
  State serialization is a compact custom binary format covering the full DR `SessionState` (incl.
  receiver chains + skipped-key seed cache) AND the SPQR ratchet (`SckaStates`/`Chain`/`Authenticator`/
  polynomial encoders+decoders/version negotiation) — round-trip tested (SpqrRatchetTests,
  SendPathTests). The app (`ChatPage`) now uses it. `AccountProtocolStore` (in-memory) remains for tests.
- ~~No one-time prekeys uploaded~~ (RESOLVED 2026-06-16; per PQXDH/X3DH spec recommendation). Linking now
  generates 100 one-time EC prekeys, uploads them (`SignalRestClient.UploadPreKeysAsync` → `PUT
  /v2/keys?identity=aci`, best-effort), and stores the privates in `account.bin`
  (`SignalAccount.AciOneTimePreKeys`). `AccountProtocolStore` seeds them; `RemovePreKey` removes the
  consumed key and re-persists via an `onChanged` callback (wired in `ChatPage`). Offline-tested
  (SendPathTests.OneTimePreKey_IsUsedAndConsumed). REMAINING: activates on next **re-link** (live
  `PUT /v2/keys` only runs then); no **PNI** one-time prekeys, no **kyber one-time** prekeys, and no
  **replenishment** when the pool runs low (PUT more when the server reports few remaining).
- **Fixed prekey IDs** (2026-06-16). `LinkingManager` hardcodes `SignedPreKeyId = 1`, `KyberPreKeyId = 1`.
  No rotation, no id allocation/tracking.
- **Single-file DPAPI account store with a constant entropy string** (2026-06-16). `AccountStore` writes
  one `account.bin`; no schema/versioning/migration beyond the `"Wingnal.Account.v1"` entropy literal.

## Networking

- **`SignalRestClient` news up its own `HttpClient`** (2026-06-16). Not pooled / DI-injected; fine for
  one-shot linking, not for app-wide use. Cert revocation check is disabled (`RevocationMode.NoCheck`)
  in `SignalTrust`.
- **`SignalWebSocket` is minimal** (2026-06-16). No keepalive/ping handling, ignores RESPONSE frames,
  single request/response correlation only — good enough for the provisioning handshake, not for the
  authenticated chat socket.
- **Pinned CA has no rotation handling** (2026-06-16). Signal's root CA is bundled as an embedded PEM
  (expires 2032-01-24). No fallback or update path if Signal rotates it.

## Sending (step 7/8)

- ~~**ChatPage send is Note-to-Self only**~~ (RESOLVED 2026-06-16, Step 8/Task 1). `ChatPage` now has a
  two-pane UI: a conversation list keyed by peer + a recipient picker (`RecipientBox`/"New"). Sent and
  received messages route to the selected peer's thread (`MessageStore.Conversations()` /
  `Recent(peer)`). The compose box targets the selected peer (own ACI = "Note to Self").
- **Messaging others: search contacts by name** (2026-06-16). The sidebar search is an `AutoSuggestBox`
  over synced contacts (`ContactsStore.Search`): type a name → pick a contact → the thread opens (we use
  their synced ACI). A raw ACI UUID still works as a fallback. The conversation list itself shows ONLY
  people you've actually chatted with (by design). Send path logs to `wingnal.log` (`send: -> … result …`);
  the log confirms sends to other users return `ok=True … sent to N device(s)`.
- **Sent messages sync to your own other devices** (2026-06-16, FIXED). When you message someone else,
  `MessageSender.SendTextAsync` now also sends a `SyncMessage.Sent` transcript (destinationServiceId +
  timestamp + the DataMessage) to your OWN ACI, so your phone/other linked devices show the outgoing
  message (`BuildSentTranscript`; best-effort, logged). Note-to-Self already reached them directly.
  Offline-tested: the transcript decrypts as an *outgoing* message routed to the real peer's thread
  (`SendPathTests.SentTranscript_DecryptsAsOutgoingToTheRealPeer`).
- ~~**Sealed-sender certs with `signer.id` rejected → "not seeing others"**~~ (FIXED 2026-06-17). LIVE BUG
  found via the running app's log: **145** inbound sealed-sender messages from real people failed with
  `InvalidMessageException: sender certificate has no server certificate`. Root cause: real Signal sender
  certificates DON'T embed the ServerCertificate (oneof `signer` field 5) — they reference it by **id**
  (field 8, production id=3) to save space, and libsignal resolves the id from a hardcoded
  `KNOWN_SERVER_CERTIFICATES` map. Our `SenderCertificateValidator` only accepted the embedded form and threw
  for every real message. FIX: embedded the known server certificates (id 2 staging, id 3 production) and
  resolve `signer.id` → that cert before the trust-root chain check. Validated against the captured
  failed-envelope-*.bin (the "no server certificate" errors are GONE; remaining are SSv2 + stale-prekey
  captures). Regression: `KnownServerCertTests` (the embedded prod cert verifies against a production trust
  root; an id-based sender cert resolves past the rejection). This was THE reason real 1:1 (and group)
  messages from others weren't appearing. Classic "passes our own round-trip, fails the real wire" — like the
  earlier SPQR field + XEdDSA-verify bugs.
- **STILL A GAP — Sealed Sender v2 (multi-recipient) receive not implemented** (16 inbound msgs throw
  `sealed sender v2 not supported`). Modern Signal **group** sends use SSv2 multi-recipient, so this likely
  blocks receiving many group messages even after the cert fix + the G1 SENDERKEY path. Next receive priority.
- **GroupsV2 receive routed in the UI** (2026-06-17). `MessageDecryptor` surfaces `DecryptedMessage.GroupId`
  + `GroupMasterKey` (from GroupContextV2, on both inbound + synced-sent); `ChatPage.OnMessage` routes group
  messages to a `group:{id}` conversation (own thread, "Group <id8>" title until a live fetch names it),
  persists the master key via `GroupStore.EnsureGroupKnown`, and skips 1:1 receipts/contact-resync for groups.
  So a decrypted group message now shows as its own conversation (not in the sender's 1:1 thread).
- **Sealed-sender receive (v1) implemented** (2026-06-16). Incoming `UNIDENTIFIED_SENDER` envelopes (how
  modern Signal clients message each other) are now decrypted: `SealedSenderDecryptor` (v1) parses the
  outer `UnidentifiedSenderMessage`, derives ephemeral+static keys (HKDF salt `UnidentifiedDelivery`,
  AES-256-CTR + HMAC-SHA256[:10]), recovers the sender from the certificate, and `MessageDecryptor` runs
  the inner ciphertext through the normal session pipeline. Round-trip + tamper tested
  (`SealedSenderTests`). GAPS: (1) **Sealed Sender v2** (multi-recipient, version 0x22/0x23) is NOT
  handled — throws; (2) the sender **certificate's server signature is not validated** against Signal's
  trust root (the inner Double-Ratchet MAC still authenticates content cryptographically, so this only
  affects server-attested sender identity); (3) inbound group sender-key (type 7) is skipped; (4) we
  don't send delivery receipts back.
- **Message list scrolls to newest** (2026-06-16). Opening a thread (and each new/sent message) scrolls
  to the last (newest) message; `MessageList` is `SelectionMode=None`/`IsItemClickEnabled=False` so a
  tap doesn't jump/scroll. Order is oldest→newest top-to-bottom (standard chat).
- **e164 recipients can't be resolved** (2026-06-16, Task 1). `RecipientResolver` accepts an ACI UUID
  directly (normalized lowercase) and rejects a `+e164` with a clear message: Signal removed the
  unauthenticated number→ACI lookup, so it needs the Contact Discovery Service (CDSI, an SGX enclave)
  which isn't implemented. *Proper:* port the CDSI handshake (or surface it from Task 3 contact sync).
- ~~**Separate send store**~~ (RESOLVED 2026-06-16, Task 1). `ChatPage` now uses ONE durable
  `SqliteSignalProtocolStore` (`protocol.db`) shared by send AND receive. Sessions are keyed by peer
  address, so one store serves the whole conversation without initiator/responder clobber: send tries
  `BuildFromExistingSessions` first (reusing a session the receive path established) and only fetches a
  bundle on the first message or a 409/410. Note-to-Self stays clobber-free because our own device is
  skipped on send. Proven by `SendPathTests.BidirectionalConversation_RoundTripsThroughOneSharedPerPeerSession`.
  MIGRATION NOTE: existing installs' old `protocol-send.db`/`protocol-recv.db` are abandoned (not
  migrated) — the next inbound prekey message / outbound bundle fetch re-establishes sessions in
  `protocol.db`.
- **Active-session reuse on send** (2026-06-16, RESOLVED the per-send prekey fetch; Sesame §3). `MessageSender`
  tries `BuildFromExistingSessions` first — if the recipient's devices already have sessions, it encrypts
  with them and sends WITHOUT a `/v2/keys` fetch; it only fetches on the first message or a 409/410
  device-set change. Now that sessions are durable (SQLite), reuse also works across restarts. (The
  `dotnet test SendLiveTests` notify hack still uses a fresh in-memory store, so it fetches once per run;
  a `wingnal-notify` CLI pointed at the durable store would avoid that.)
- ~~`MessageSender` has no 409/410 device-set recovery~~ (RESOLVED 2026-06-16 via Sesame spec §3.3).
  On a 409 (mismatched) / 410 (stale) response, `SendTextAsync` now re-fetches the authoritative device
  list (`GET /v2/keys/{id}/*`, which reconciles both added and removed/rotated devices) and retries,
  bounded to `MaxSendAttempts=3` per Sesame's anti-loop guidance. (Per-device session insert/archive
  semantics from Sesame §3 are not yet modeled — we use one in-memory store and re-establish on retry.)
- **No `wingnal-notify` CLI** (2026-06-16). The "message me when done" flow shells out to the gated
  `SendLiveTests` via `dotnet test` (slow). A tiny console sender would be cleaner + hook-able. See
  memory feedback_notify_when_done.

## App architecture / UI

- **No real MVVM / DI yet** (2026-06-16). `MainWindow` directly `new`s `AccountStore` and routes by
  `AccountStore.Exists`; `LinkDevicePage` constructs the linking stack inline. *Proper:* view models +
  a service/DI layer.
- **`ChatPage` is a placeholder** (2026-06-16). Shows account info only; messaging UI is steps 6–8.
- **"Unlink & re-link" doesn't call a server unlink** (2026-06-16). `ChatPage.OnUnlinkClick` now wipes
  ALL local state (account.bin + messages.db + contacts.db + protocol.db sessions/identities, via each
  store's `Clear()`) and clears the in-memory UI — so a re-link starts clean and never reuses sessions
  tied to the old identity keys. It still does NOT call a server unlink (`DELETE /v1/devices/...`), so
  the device stays registered on the account until removed from the phone.
- **Device name hardcoded to "Wingnal"** (2026-06-16). `LinkingManager` default; no UI to set it.

## Messaging / receive (step 6)

- ~~Sessions are in-memory only~~ (RESOLVED 2026-06-16). The app uses `SqliteSignalProtocolStore`;
  sessions + learned identities survive restarts (SessionRecord/SessionState/SPQR serialization added).
  ~~Send and receive use SEPARATE DB files~~ → UNIFIED 2026-06-16 (Task 1) to ONE `protocol.db` shared by
  send + receive (see "Separate send store" under Sending).
- **Ack before decrypt** (2026-06-16). `ChatReceiver` replies 200 to every `/api/v1/message` before
  attempting decryption, so a message we can't decrypt is dropped from the server queue (avoids a
  redelivery loop). *Proper:* ack only after successful persist; handle decrypt failures explicitly.
- **No outgoing keepalive** (2026-06-16). We answer inbound keepalives but don't send our own, so the
  socket may idle-timeout (~60s). Fine for draining the queue on connect; not for staying connected.
- ~~Chat socket auth via query params~~ (RESOLVED 2026-06-16). Query-param auth connected but landed
  UNAUTHENTICATED (upgrade OK, zero frames). Switched to `Authorization: Basic {aci.deviceId:password}`
  header — server then delivered a queued message + `/api/v1/queue/empty`. Header auth is correct.
- **ack-after-success only** (2026-06-16). ChatReceiver now acks a /api/v1/message frame only after a
  successful decrypt; a message we can't decrypt is NOT acked and the server redelivers it every
  reconnect. Good for debugging, but a permanently-undecryptable message blocks the queue. Revisit once
  decryption is solid (then ack-and-log-failures instead).
- **Receive only handles ACI sessions + DataMessage/SyncMessage.Sent text** (2026-06-16). PNI sessions,
  sealed sender, receipts, typing, and non-text content are ignored. No one-time prekeys means every
  inbound session uses the last-resort kyber prekey.

## Groups (Task 2 — Sender Key crypto core)

- **Sender Key primitive is crypto-core only; not wired into the app** (2026-06-16). `Wingnal.Protocol/
  Groups/` (SenderKeyMessage/SKDM, state/record, GroupSessionBuilder/Cipher, in-memory store) is
  byte-exact with libsignal v0.96.1 and offline-tested (one→many, OOO/skip, tamper, wire round-trip). It
  does NOT join or message real Signal groups — that needs Groups v2 (zkgroup credentials, group master
  key, groups storage service, membership, sealed sender). Full plan in `docs/GROUPS.md`.
- **Sender-key state is in-memory only** (2026-06-16). No `storage.proto` SenderKeyRecordStructure
  serialization yet; `InMemorySenderKeyStore` only. *Proper:* serialize + a SQLite `ISenderKeyStore`
  before any app use (Step A in docs/GROUPS.md).
- **31-bit chain id via `RandomNumberGenerator`** (2026-06-16). `GroupSessionBuilder.Create` uses
  `RandomUInt32() >> 1` (matches libsignal's Java-compat 31-bit id). Fine.

## Sync & history (Task 3)

- ~~link'n'sync history backfill is scaffolded, not built~~ (BUILT 2026-06-16). Full engine in
  `Wingnal.Service/Sync/`: `BackupKey` (HKDF chain, validated byte-exact vs libsignal vector),
  `BackupReader` (HMAC+AES-CBC+unpad+gzip+varint frames; parser validated vs libsignal canonical
  backup), `BackupImporter` (Recipient/Chat/ChatItem → contacts+messages), vendored `Protos/Backup.proto`,
  `MessageHistoryImporter` orchestrator. QR advertises `backup5`; `LinkingManager` captures
  `ephemeralBackupKey`; `ChatPage` runs the backfill once on a fresh link+sync connect. 91 offline tests.
  LIVE-ONLY caveats (untested without a re-link): the `transfer_archive` descriptor shape + CDN object
  path (`/attachments/{key}`), CDN cert pinning (may be a public CA, not the bundled Signal CA), and
  whether the archive is gzip'd vs raw. Old messages require a RE-LINK (history transfers only at link
  time; Signal stores none server-side). LIVE-CONFIRMED working: a re-link imported 3473 messages + 53
  contacts. See `docs/SYNC.md`.
- **link'n'sync re-link reliability hardened** (2026-06-16). After a live re-link that didn't restore:
  (1) the one-time `ephemeralBackupKey` is cleared ONLY on a definitive outcome (imported, or primary
  reports no archive); on a transient failure (poll timeout / network / download error)
  `MessageHistoryImporter.Result.ShouldRetry=true` and `ChatPage` KEEPS the key so the next launch retries
  (previously cleared regardless → lost the single chance if the phone was slow to upload). (2) A
  `_historyImportStarted` guard stops the observed double-import (archive written twice). (3)
  `BackupImporter` dedups via `MessageStore.ExistingKeys()` (peer|ts|outgoing|body) so retries/re-imports
  never duplicate. NOTE: history only arrives if the phone offers link+sync — the user must tap "transfer
  messages" on the phone during each re-link.
- **Conversation list showed a wrong "latest message" date after import** (2026-06-16, FIXED). Symptom:
  the newest message showed as months old (e.g. 1/8/2026) even though the data was correct (timestamps
  spanned Dec 2025 → today). Cause: `MessageStore.Conversations()` picked each peer's row by `MAX(id)`
  (last *inserted*) — but a bulk import inserts in archive order, not time order. Now uses `MAX(timestamp)`
  (SQLite fills the bare columns from the max-timestamp row) so the list shows + sorts by the truly newest
  message. Thread view (`Recent`) was already `ORDER BY timestamp ASC` (correct).
- **Duplicate messages from the earlier double-import** (2026-06-16, FIXED). `MessageStore.Deduplicate()`
  (DELETE keeping MIN(id) per peer+timestamp+outgoing+body) runs once on `ChatPage` load to clean exact
  duplicates; the import dedup prevents new ones. (Send-vs-import near-duplicates with slightly different
  ms timestamps aren't caught — minor.)
- **CDN cert pinning unverified** (2026-06-16). `AttachmentDownloader` validates via `SignalTrust` (the
  bundled Signal CA), but Signal's CDNs (cdn.signal.org / cdn2 / cdn3) may chain to a different (public)
  CA — the download path is untested live (only `AttachmentCipher.Decrypt` is offline-tested). Revisit
  when wiring real attachment/contacts-blob downloads; may need a CDN-specific CA or OS trust for CDN.
- **SyncMessage.Read surfaced but not persisted** (2026-06-16). `SyncProcessor.ReadReceiptReceived`
  fires per read receipt, but there's no read column in `messages.db` yet, so read state isn't stored.
- **Contacts sync imports ACI + name/number only** (2026-06-16). `SyncProcessor.ImportContacts` skips
  e164-only (ACI-less) contacts and ignores avatars/expireTimer/inbox beyond name. GROUPS sync omitted
  (removed from the sync protocol; groups via storage service — docs/GROUPS.md).
- **Sync requests sent every connect** (2026-06-16). `ChatPage` fires CONTACTS/BLOCKED/CONFIGURATION
  requests on each chat connect; no throttle/once-per-link guard. Fine (cheap), but could be gated.

## Resolved

- ~~KEM ciphertext prefix for messaging~~ (RESOLVED 2026-06-16). `SessionBuilder` now serializes the
  kyber ciphertext with the `0x08` prefix on the wire and strips it on decapsulate.
