# Groups in Wingnal — status + full Groups v2 build plan

Last updated 2026-06-16. This is the **detailed, executable plan** for taking Wingnal from "group
crypto primitive only" to real Signal group chats (Groups v2 / "GV2"). It is written to be resumed
across many sessions; each phase has concrete files, pinned facts, and a **test gate** that must be
green before the next phase starts. Reference source is libsignal `rust/` tag **v0.96.1** (same tag the
Sender Key + SPQR ports were pinned to).

---

## Reality check (decided 2026-06-16, before writing this plan)

Two facts were verified against the installed toolchain because they decide the whole effort:

1. **BouncyCastle 2.5.1 has NO Ristretto255.** Its XML surface exposes only `Math.EC.Rfc8032.Ed25519`
   and `Math.EC.Rfc7748.X25519Field` (the latter is already wrapped in
   `Wingnal.Protocol/Curve/Ed25519Ct.cs`). There is no public Ristretto group element, no scalar-mod-ℓ
   type, no multiscalar mul. **Therefore zkgroup must be hand-ported** (Ristretto255 group + `Scalar`
   field + `poksho` Schnorr proofs), reusing BC's `X25519Field` for the base field GF(2²⁵⁵−19) and the
   `ScReduce`/`ScMulAdd` already in `Ed25519Ct` for scalar reduction. This is a Kyber/SPQR-scale port and
   is **the long pole** of the whole feature.
2. **BouncyCastle 2.5.1 HAS AES-256-GCM-SIV** (`Org.BouncyCastle.Crypto.Modes.GcmSivBlockCipher`). zkgroup
   encrypts the group's title/avatar/description blobs with AES-256-GCM-SIV, so that part binds to BC
   instead of being hand-ported. Validate our wrapper against an RFC 8452 test vector before use.

**Hard rule for the whole feature:** every crypto phase is validated against libsignal's own test vectors
**before** any network call. zkgroup has deterministic vectors (`rust/zkgroup/src/lib.rs` `tests` +
`rust/zkgroup/tests/`) that fix the server's random params, so client/server flows reproduce byte-exactly
offline. Wrong ZK math fails silently (server returns 403 with no detail), so KATs are non-negotiable.

---

## Phase 0 — DONE: the crypto building blocks already in the tree

These are complete and tested; GV2 builds directly on them. Do not re-port them.

- **Sender Key messaging primitive** (`Wingnal.Protocol/Groups/`, byte-exact vs libsignal v0.96.1). One
  ciphertext that every member decrypts: `SenderKeyMessage`/`SenderKeyDistributionMessage`,
  `SenderChainKey`/`SenderMessageKey` (HKDF "WhisperGroup" 48B → iv‖cipherKey), `SenderKeyState`
  (chainId, signing key, bounded skipped-key FIFO `MAX_MESSAGE_KEYS=2000`), `SenderKeyRecord`
  (`MAX_SENDER_KEY_STATES=5`), `GroupSessionBuilder` (Create→SKDM / Process), `GroupSessionCipher`
  (Encrypt/Decrypt, AES-256-CBC, `MAX_FORWARD_JUMPS=25000`), `InMemorySenderKeyStore`. Pinned facts:
  version byte `0x33`; `distribution_uuid` serialized RFC-4122/big-endian (`SenderKeyWire.DistributionBytes`);
  XEdDSA sig over `version‖protobuf`. Tests: `Wingnal.Tests/Groups/GroupCipherTests.cs`.
- **Sealed sender (UD) for 1:1** — `SealedSenderDecryptor` (receive v1 + `EncryptWithCertificate`),
  `SenderCertificateValidator` (cert chain vs production trust roots), `MessageSender.TrySealedAsync`
  (opportunistic sealed send w/ auth fallback), `ProfileKeyStore`, `UnidentifiedAccess.DeriveAccessKey`.
  GV2 fan-out reuses `EncryptWithCertificate` per member device. (Sealed Sender **v2** multi-recipient is
  NOT done — see Phase G; v1-per-device is sufficient to ship.)

**What's still missing for real groups:** durable Sender Key storage, the entire zkgroup credential
system, the group storage-service client, membership/change application, and the group DataMessage
wiring + UI. That is Phases A–H below.

---

## Phase A — Sender Key persistence (SQLite store + state serialization)

**Goal:** the Sender Key primitive survives app restart, mirroring how `SqliteSignalProtocolStore`
persists the Double Ratchet today. No new crypto.

- `Wingnal.Protocol/Groups/SenderKeyRecordSerialization.cs` — custom binary (or reuse the
  existing `SessionRecord` serialization style) for `SenderKeyRecord` → bytes: per state the chainId,
  iteration, chainKey, signing key pair, and the skipped-key FIFO cache. (libsignal uses
  `storage.proto SenderKeyRecordStructure`; we already chose custom binary for sessions, stay consistent.)
- `Wingnal.Service/Account/SqliteSenderKeyStore.cs` — `ISenderKeyStore` over SQLite, blobs
  DPAPI-wrapped via `LocalCipher` (same pattern as `SqliteSignalProtocolStore`). Key = (senderAddress,
  distributionId).
- **Test gate:** `SenderKeyPersistenceTests` — build a 3-member synthetic group, exchange a few messages,
  serialize→restore the store, confirm decryption (incl. an out-of-order/skipped message) continues
  across the restart. Offline. Must keep the existing 121 green.

Independently useful and zero-risk; do this first to lock the storage shape.

---

## Phase B — zkgroup math foundation (`Wingnal.Protocol/ZkGroup/Curve/`)

**Goal:** a constant-time-ish Ristretto255 group + scalar field, validated against curve25519-dalek
vectors. This is the bottom of the long pole.

- `Scalar25519.cs` — integers mod ℓ = 2²⁵² + 27742317777372353535851937790883648493. Ops: add, sub, mul,
  negate, invert (Fermat or `ScMulAdd`-based), `FromBytesModOrder` (32B LE), `FromBytesModOrderWide`
  (64B LE → reduce; reuse `Ed25519Ct.ScReduce`), `ToBytes`. Start on `BigInteger` for clarity; the
  reduction helpers in `Ed25519Ct` (ref10 `sc_reduce`/`sc_muladd`) are the constant-time upgrade path.
- `RistrettoPoint.cs` — edwards25519 extended (X:Y:Z:T) coordinates over BC `X25519Field`, with the
  **Ristretto** layer on top: canonical 32-byte encode/decode (the Ristretto equality + sign rules),
  `FromUniformBytes` (Elligator2, 64B → point, for hash-to-group), add, negate, scalar-mul
  (`mul(Scalar)`), and the fixed basepoint. Reuse the field add/sub/mul/sqr/invert/cmov already proven in
  `Ed25519Ct` (extract them into a shared `Field25519` helper rather than duplicating).
- `RistrettoGenerators.cs` — `RISTRETTO_BASEPOINT` + deterministic generator derivation via the SHO
  (Phase C) — but the basepoint constant can land here.
- **Test gate:** `RistrettoVectorTests` — port the curve25519-dalek canonical vectors: the 16
  multiples-of-basepoint encodings, the Elligator/`from_uniform_bytes` test, decode-rejects-non-canonical,
  and scalar arithmetic identities. Byte-exact. (This is the gate that proves the group is correct before
  any credential logic depends on it — treat like the Ed25519Ct cross-check.)

RISK: Ristretto encode/decode sign conventions are subtle (the `IS_NEGATIVE`/`abs` rules). Budget real
time here and lean on the dalek vectors. ~2 dense files + heavy testing.

---

## Phase C — poksho (SHO + Schnorr proof system) (`Wingnal.Protocol/ZkGroup/Poksho/`)

**Goal:** the Fiat-Shamir transcript + generic Σ-protocol that every zkgroup credential is expressed in.
Must be byte-exact or proofs verify nowhere.

- `Sho.cs` — the "stateful hash object": `ShoHmacSha256` (and/or `ShoSha256`) with libsignal's exact
  absorb/ratchet/squeeze construction. Used to (a) derive `SystemParams` generators, (b) hash proof
  transcripts, (c) `get_point`/`get_scalar` (hash-to-group / hash-to-scalar). Byte-exactness is verified
  against poksho's own test vectors (`rust/poksho/tests`).
- `Statement.cs` + `Proof.cs` — the generic linear-relation proof: a statement is a set of equations
  "point = Σ scalarᵢ · generatorᵢ"; the prover knows the scalars, the verifier checks. This is the engine
  behind AuthCredential/ProfileKeyCredential presentations.
- **Test gate:** `PokshoVectorTests` — SHO output vectors + a known Schnorr proof prove/verify round-trip
  + a tampered-proof rejection, matching poksho vectors.

RISK: medium. The SHO byte layout and the proof challenge computation must match exactly. The proof
framework itself is mechanical once SHO is right.

---

## Phase D — zkgroup credentials, ciphertexts, params (`Wingnal.Protocol/ZkGroup/`)

**Goal:** everything the group server speaks, expressed in zkgroup. Pure crypto; validated offline.

- `GroupSecretParams.cs` / `GroupPublicParams.cs` — derive `GroupSecretParams` from the 32-byte
  **group master key** via SHO; derive `GroupPublicParams` + the 32-byte **group identifier** from it.
  (The Sender Key **distribution id** for a group derives from the group id + sender, per libsignal
  `sender_key_name` — wire this into Phase G.)
- `SystemParams.cs` — the fixed credential-system generators, derived deterministically via SHO. Must
  reproduce libsignal's constants exactly (assert against the hard-coded `SystemParams::get_hardcoded()`
  bytes in zkgroup).
- `UuidCiphertext.cs` / `ProfileKeyCiphertext.cs` — encrypt a `ServiceId`/profile key under
  `GroupSecretParams` (deterministic, so the server can match without learning the ACI). Reuse the
  `ServiceId` binary form from `Wingnal.Service/ServiceIds.cs`.
- `AuthCredentialWithPni.cs` + `AuthCredentialWithPniPresentation.cs` — receive+verify the server's
  `AuthCredentialWithPniResponse`, store the credential, and build the **presentation** (the ZK proof) put
  in the `Authorization` header for group-server calls.
- `ProfileKeyCredential` / `ExpiringProfileKeyCredential` + presentation — needed to add members by proving
  knowledge of their profile key (used in `GroupChange` for adds).
- `GroupAttributeBlob` encryption — `ClientZkGroupCipher.EncryptBlob/DecryptBlob` using **AES-256-GCM-SIV**
  (BC `GcmSivBlockCipher`) under a key derived from `GroupSecretParams`. Wraps title/avatar/description.
- **Test gate:** `ZkGroupVectorTests` — port libsignal's zkgroup integration vectors: fixed
  `ServerSecretParams` seed → issue an AuthCredentialWithPni → client verifies → builds presentation →
  server-side verify accepts; UuidCiphertext/ProfileKeyCiphertext round-trip; blob enc vs vector. All
  byte-exact, offline. **This is the gate that proves we can talk to the real group server before we try.**

This is the largest single phase. Do not start Phase E until these vectors pass.

**STATUS (2026-06-16):** split in two after discovering the dependency surface.
- **D1 DONE** — `Wingnal.Protocol/ZkGroup/GroupSecretParams.cs`: master-key → group_id + blob_key
  derivation and AES-256-GCM-SIV blob encrypt/decrypt-with-padding (BC `GcmSivBlockCipher`). Gated by
  zkgroup's `test_encrypt_with_padding` vectors (`GroupSecretParamsTests`). Enough to derive a group id
  (route inbound group messages — Phase G1) and decrypt group title/avatar blobs.
- **D2 REMAINING (large)** — the member-hiding credential/ciphertext layer pulls in TWO more ports that
  weren't visible from the top-level plan: (1) the **zkcredential** crate (the attribute/credential ZK
  system that `uid_encryption` / `profile_key_encryption` / AuthCredential all route through), and
  (2) **Lizard** encoding — `RistrettoPoint::lizard_encode::<Sha256>(16 bytes)` in the
  *curve25519-dalek-signal fork* (NOT RFC 9496, NOT upstream dalek), plus `lizard_decode` for decryption,
  plus `get_point_single_elligator` (single-Elligator map; only the double `FromUniformBytes` is ported).
  Then `UuidCiphertext` / `ProfileKeyCiphertext` / `AuthCredentialWithPni` + presentations. Fetch
  `rust/zkcredential/src` + the lizard impl from the fork; validate against zkgroup integration vectors.

---

## Phase E — group storage-service client (`Wingnal.Service/Groups/`)

**Goal:** fetch and decrypt the real group state for a group the user is already in.

- Pinning: `storage.signal.org` is a **separate host** from chat — confirm whether it chains to the same
  bundled Signal CA (`SignalTrust`) or needs its own pin; add to `SignalServiceConfig`.
- `Protos/Group.proto` (vendored) — `Group`, `GroupChange`, `GroupChanges`, `Member`, `PendingMember`,
  `RequestingMember`, `AccessControl`. All member identity fields are zkgroup ciphertexts.
- `GroupsApiClient.cs` — `GET /v1/groups` (auth = `AuthCredentialWithPniPresentation` in the header),
  `GET /v1/groups/logs/{fromRevision}` (incremental `GroupChanges`), `PATCH /v1/groups` (apply a change).
- `GroupStateCodec.cs` — decrypt a fetched `Group` into a plaintext local model (member ACIs via
  `UuidCiphertext` decrypt, title via blob decrypt, roles, revision).
- **Test gate:** `GroupFetchLiveTests [Category=Live]` — using a real linked account that's in a group,
  fetch + decrypt the group and assert the member list/title match what the phone shows. Offline unit test
  for `GroupStateCodec` against a captured (decrypted-locally) `Group` blob.

RISK: depends entirely on Phase D being byte-exact (a wrong presentation → opaque 403).

---

## Phase F — membership model + GroupChange application

**Goal:** maintain local group state and apply server changes safely.

- `Wingnal.Service/Groups/GroupStore.cs` (SQLite, encrypted via `LocalCipher`) — per-group: masterKey,
  revision, decrypted roster (ACI, role), title/avatar, access control.
- `GroupChangeApplier.cs` — apply add/remove/promote/invite/requesting-member diffs, **verify the server's
  signature on each `GroupChange`**, reconcile `GET /v1/groups/logs` incrementally to the latest revision.
- **Test gate:** `GroupChangeTests` — apply a sequence of captured changes to a base state, assert the
  resulting roster/revision; reject a change with a bad server signature.

---

## Phase G — group DataMessage wiring (the part the user sees working)

**Goal:** send and receive actual group messages. Two milestones — receive first (cheaper), then send.

- **G1 (receive-only, can land right after Phase A — no zkgroup needed to *decrypt*):** detect
  `DataMessage.GroupV2 { masterKey, revision }` on inbound (sealed) messages; derive the group id (needs
  the Phase B/D `GroupSecretParams` for the id, but NOT the full credential system); process any inbound
  `SenderKeyDistributionMessage` (already on `Content`) via `GroupSessionBuilder.Process`; decrypt the
  `SenderKeyMessage` with `GroupSessionCipher`; route into a group thread keyed by group id. Roster/names
  show as raw ACIs until Phase E fills them in. **This gives early visible value** — group messages start
  appearing — before the storage-service work is finished.
- **G2 (send):** attach `GroupContextV2 { masterKey, revision }` to the `DataMessage`; encrypt the body
  once with `GroupSessionCipher`; for each member device (roster from Phase E/F), wrap the
  `SenderKeyMessage` as **sealed sender** via the existing `EncryptWithCertificate` and fan out; first
  distribute our `SenderKeyDistributionMessage` (also sealed 1:1) to members who don't have our current
  sender key. Handle 409/410 device-set changes per member (reuse the Sesame retry logic in
  `MessageSender`). Optionally adopt **Sealed Sender v2** (multi-recipient) later to cut fan-out bandwidth.
- **Test gate:** `GroupMessagingTests` — offline 3-member loopback (build group state in-proc, A sends,
  B and C both decrypt, incl. a late-joiner who needs the SKDM); a live send to a real group gated
  `[Category=Live]`.

---

## Phase H — group UI

**Goal:** groups are first-class in the app.

- Group conversations in the conversation list (group avatar/title from decrypted state), a member roster
  view, "new group"/add-member/leave flows (each a `PATCH /v1/groups` `GroupChange`), group typing/receipt
  fan-out (reuse Phase 0 + the receipts work), and the "X added/removed Y" change banners in-thread.
- Reuses the existing `ChatPage` two-pane shell; a group thread is just a conversation keyed by group id.

---

## Dependency graph (what unblocks what)

```
Phase 0 (done) ─┬─> A (persistence) ─────────────────────────────> G1 (receive groups)  [early value]
                │
                └─> B (Ristretto+Scalar) ─> C (poksho) ─> D (credentials/ciphertexts)
                                                              │
                                                              └─> E (storage API) ─> F (membership) ─> G2 (send) ─> H (UI)
```

So the cheapest path to *visible* groups is **A → (B + D-just-enough-for-group-id) → G1**. Full
send/management requires the whole B→C→D→E→F→G2 spine. zkgroup (B+C+D) is ~60% of the total effort and
must be vector-perfect before E.

## Risk register

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Ristretto255 hand-port correctness | High | dalek canonical vectors (Phase B gate); extract proven field ops from `Ed25519Ct` |
| poksho SHO byte-exactness | High | poksho vectors (Phase C gate) — proofs verify nowhere if off |
| zkgroup presentation rejected by server (opaque 403) | High | full offline issue→present→verify vector (Phase D gate) before any network |
| Scalar arithmetic not constant-time (BigInteger) | Medium | acceptable for v1 (client-side, ephemeral randomness); harden with ref10 `sc_*` later |
| storage.signal.org cert pin differs from chat | Low | verify host CA during Phase E; reuse `SignalTrust` if same |
| Sealed Sender v1 fan-out bandwidth on large groups | Low | ship v1-per-device; add SSv2 multi-recipient later |

## How to resume

Start at the lowest unfinished phase; do not skip a test gate. Keep the two baselines green every phase:
`dotnet test Wingnal.Tests/Wingnal.Tests.csproj --filter "Category!=Live&Category!=Kat"` and
`dotnet build Wingnal/Wingnal.csproj -p:Platform=x64`. Pin all ports to libsignal v0.96.1. Record each
phase's completion + gotchas in `memory/project_build_plan.md` and `SHORTCUTS.md`, same as prior steps.
