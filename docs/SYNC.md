# Message sync & history download (Task 3)

Status as of 2026-06-16. Scope: backfill contacts/groups/config on a freshly linked device, plus the
foundational attachment-download primitive and the link'n'sync message-history transfer. Beyond the
original MVP (link + 1:1 text) — built incrementally; the heavy parts are documented here.

## What's built

### 1. SyncMessage.Request on connect  ✅
`ChatPage.RequestSyncAsync` sends a `SyncMessage.Request` to our own ACI for **CONTACTS**, **BLOCKED**,
and **CONFIGURATION** right after the chat socket connects (`MessageSender.SendSyncRequestsAsync`). This
asks the primary to push account state; responses arrive as inbound sync messages on the socket. GROUPS
is intentionally omitted — it was removed from the sync protocol (`reserved /*GROUPS*/ 2` in
`SyncMessage.Request.Type`); groups now live in the storage service (see docs/GROUPS.md).

### 2. Attachment-download primitive  ✅ (offline-tested)
`Wingnal.Service/Attachments/`:
- `AttachmentCipher` — decrypts a CDN blob: verifies the whole-blob **SHA-256 digest**, verifies
  **HMAC-SHA256** over `iv‖ciphertext` (macKey = key[32..64]), **AES-256-CBC** decrypts (cipherKey =
  key[0..32]), and truncates to the declared plaintext `size` (strips bucket padding). Also `Encrypt`
  for tests. Validated by `AttachmentCipherTests` (round-trip, bucket truncation, digest/MAC/keylen
  rejection).
- `AttachmentDownloader` — `GET {cdnUrl(cdnNumber)}/attachments/{cdnKey|cdnId}` (cert-pinned), then
  `AttachmentCipher.Decrypt`. Reused by contacts sync now and media later.

This is the foundational primitive (used by contacts/groups sync and, later, media + the history
archive). Only the decrypt half is offline-testable; the CDN GET is live-only.

### 3. Inbound Contacts sync → ContactsStore  ✅ (parse/persist offline-tested)
- `ContactRecordStream.Parse` — parses the decrypted contacts blob: a flat stream of
  `[varint length][ContactDetails]` records, each optionally followed by `[avatar.length]` inline avatar
  bytes (Signal's DeviceContacts stream format).
- `ContactsStore` (SQLite `contacts.db`) — upserts ACI → name/number/inboxPosition.
- `SyncProcessor` — on an inbound `SyncMessage.Contacts`, downloads the blob (primitive #2), imports it
  (`ImportContacts`), and persists. Read receipts (`SyncMessage.Read`) raise `ReadReceiptReceived`.
- `ChatReceiver` now decrypts to a `Result{Content, Message}` and routes sync messages to `SyncProcessor`
  via an `onSync` callback; `ChatPage` refreshes conversation **titles** from `ContactsStore` so the list
  shows names instead of raw ACIs.
- Tested: `SyncContactsTests` (stream parse incl. inline avatar; import → names persisted).

Read state is surfaced (`ReadReceiptReceived`) but not yet persisted to a read column — a follow-up.

## link'n'sync message-history backfill — BUILT (engine offline-validated; live path needs a re-link)

Signal's "A Synchronized Start for Linked Devices." The import engine (key derivation → decrypt →
gunzip → parse `backup.proto` → populate stores) is implemented and offline-tested; the only
live-untestable parts are the CDN poll/download and the actual re-link (Signal doesn't store history
server-side, so old messages only transfer **at link time** — an already-linked device must re-link,
removing the Wingnal device on the phone and tapping "transfer/sync messages").

### Built components (`Wingnal.Service/Sync/`, `Attachments/`)
- `BackupKey` — HKDF chain ephemeralBackupKey → backup_id → MessageBackupKey (hmac[32]‖aes[32]).
  **Validated byte-exact against libsignal v0.96.1's own test vector** (`BackupKeyTests`).
- `BackupReader` — container `IV[16]‖AES-256-CBC‖HMAC[32]` → MAC-verify → decrypt → PKCS7 unpad →
  gzip inflate → varint-delimited `BackupInfo` + `Frame`s. **Frame parser validated against libsignal's
  canonical-backup.binproto**; container round-trip + tamper rejection tested (`BackupReaderTests`).
- `BackupImporter` — `Recipient`→contacts, `Chat`+`ChatItem`(StandardMessage text)→per-peer messages
  (correct direction; Self→"Note to Self"). End-to-end offline test (`BackupImporterTests`).
- `Protos/Backup.proto` — vendored libsignal `backup.proto` (csharp_namespace `…Protos.Backup`).
- `MessageHistoryImporter` — orchestrates poll → download → derive → read → import.
- `AttachmentDownloader.DownloadRawAsync` — raw CDN GET for the archive (decrypted by BackupReader, not
  AttachmentCipher).
- `SignalRestClient.WaitForTransferArchiveAsync` — `GET /v1/devices/transfer_archive` long-poll.
- Linking: QR now advertises the `backup5` capability (`ProvisioningManager.LinkAndSyncCapability`);
  `LinkingManager` captures `ProvisionMessage.ephemeralBackupKey` into `SignalAccount.EphemeralBackupKey`.
- `ChatPage` — on first connect after a link+sync re-link, runs the backfill once, then clears the
  one-time key, persists, and reloads the conversation list.

### Remaining (live-only / caveats)
- **Needs a real re-link to exercise** the poll/download path (offline tests cover crypto+parse+import).
- **Transfer-archive descriptor shape** (`RemoteAttachment` cdn/key) and the CDN object **path**
  (`/attachments/{key}`) are taken from Signal-Server source but untested live — verify on first re-link.
- **CDN cert pinning** — see SHORTCUTS.md; the CDN may chain to a public CA, not the bundled Signal CA.
- **`backup_id`/derivation assumes no forward-secrecy token** (OLD_DST), which is the link'n'sync case.
- Importer covers 1:1 text only (groups/attachments/reactions/other ChatItem types skipped by design).

### Historical: original plan (now implemented)

### The flow (confirmed from Signal-Android Provisioning.proto + Signal-Server DeviceController)
1. **Capability at link.** The new device advertises the link+sync capability in the QR/link request.
   The primary then includes `ephemeralBackupKey` (32 bytes, **Provisioning.proto field 14**) in the
   encrypted `ProvisionMessage` (also `accountEntropyPool` 15, `mediaRootBackupKey` 16, `aciBinary` 17,
   `pniBinary` 18; `masterKey` 13 is deprecated in favor of `accountEntropyPool`). Wingnal's
   `Provisioning.proto` now carries these fields.
2. **Primary exports + uploads.** The primary serializes its history as a **Signal Backup** file
   (`backup.proto`: a `BackupInfo` header then a length-delimited stream of `Frame`s —
   `AccountData`, `Recipient`, `Chat`, `ChatItem`, `StickerPack`, `AdHocCall`, …), **gzip**-compresses
   it, encrypts it (AES-CBC + HMAC, keys derived from `ephemeralBackupKey`), uploads it to the CDN, and
   calls `PUT /v1/devices/transfer_archive` (`TransferArchiveUploadedRequest{destinationDeviceId,
   destinationDeviceRegistrationId, transferArchive}`).
3. **New device downloads + imports.** The new device long-polls
   `GET /v1/devices/transfer_archive?timeout=…` → a `RemoteAttachment{cdn, key}` (or a
   `RemoteAttachmentError`), downloads the blob (primitive #2), decrypts with the
   `ephemeralBackupKey`-derived keys, gunzips, parses the backup frames, and imports into the local
   stores.

### Client scaffold in place
- `Provisioning.proto` — link'n'sync fields added (step 1), so a future linking flow can capture
  `ephemeralBackupKey`.
- `SignalRestClient.WaitForTransferArchiveAsync` — the step-3 long-poll, returning
  `TransferArchiveDescriptor` (cdn/key or error), or null on a 204 timeout.
- `Wingnal.Service/Sync/MessageHistoryImporter` — the seam: `DeriveBackupKey` and `ImportAsync` throw
  `NotImplementedException` pointing here.

### What's left to implement (the heavy parts)
- **A: capture `ephemeralBackupKey` at link.** Have `LinkDevicePage` advertise the link+sync capability
  and stash `ProvisionMessage.ephemeralBackupKey` (the linking layer already decrypts the
  ProvisionMessage — just read the new field).
- **B: backup key derivation.** Port libsignal's `MessageBackupKey` derivation
  (HKDF over `ephemeralBackupKey`/`accountEntropyPool` → `aesKey` + `hmacKey`; info strings per the
  `libsignal/rust/message-backup` crate). Implement `MessageHistoryImporter.DeriveBackupKey`.
- **C: backup container decrypt + gunzip.** The archive is `iv‖AES-256-CBC(ct)‖HMAC` (same shape as the
  attachment primitive — likely reuse `AttachmentCipher` with the derived 64-byte key), then gzip-inflate.
- **D: `backup.proto` frame import.** Add `backup.proto` to `Wingnal.Service/Protos/`, stream-parse the
  length-delimited `Frame`s, and map: `Recipient`→`ContactsStore`/conversation, `Chat`+`ChatItem`→
  `MessageStore` (with proper timestamps/authors/threads). This is the bulk of the work (the backup
  schema is large) and should be staged: header → recipients → chats → chat items.
- **E: wire `MessageHistoryImporter` into the post-link path** (poll → download → B/C/D → populate
  stores), with progress UI.

Until A–E land, a freshly linked Wingnal shows live messages from connect onward + synced contact names,
but does not backfill historical messages. (Note: link'n'sync is also **opt-in and time-bounded** on the
primary — the archive is only offered briefly right after linking.)

## Endpoints / protos referenced
- `GET /v1/devices/transfer_archive?timeout=` → `RemoteAttachment | RemoteAttachmentError` (new device).
- `PUT /v1/devices/transfer_archive` (primary, not us).
- `SignalService.proto`: `SyncMessage.{Request,Contacts,Blocked,Configuration,Read}`, `ContactDetails`,
  `AttachmentPointer`.
- `Provisioning.proto`: `ProvisionMessage.{ephemeralBackupKey=14, accountEntropyPool=15,
  mediaRootBackupKey=16, aciBinary=17, pniBinary=18}`.
- `backup.proto` (libsignal `proto/backup.proto`) — NOT yet vendored; needed for step D.
