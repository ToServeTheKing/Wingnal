# Releasing Wingnal

Releases are automated by [`.github/workflows/release.yml`](.github/workflows/release.yml).
Pushing a version tag builds signed MSIX packages (x64 + ARM64) and publishes a
GitHub Release with auto-generated notes.

## Cutting a release

The **git tag is the source of truth for the version.** You do not need to edit
`Package.appxmanifest` first — the workflow stamps the tag's version into the
manifest at build time.

```sh
git tag v1.0.2          # must be vMAJOR.MINOR.PATCH (optionally .REVISION)
git push origin v1.0.2
```

The workflow then:

1. Derives the version from the tag (`v1.0.2` → `1.0.2.0`).
2. Stamps it into `Wingnal/Package.appxmanifest`.
3. Builds and signs an MSIX for x64 and ARM64.
4. Creates a GitHub Release named after the tag, with the MSIX files attached
   and release notes generated from the commits/PRs since the last tag.

To adjust the notes, edit the release on GitHub after it's created.

## Code signing

MSIX packages must be signed to install. The workflow looks for two repository
secrets:

| Secret | Description |
| --- | --- |
| `SIGNING_CERTIFICATE` | Base64-encoded `.pfx` code-signing certificate. |
| `SIGNING_CERTIFICATE_PASSWORD` | Password for the `.pfx`. |

Add them under **Settings → Secrets and variables → Actions**.

To base64-encode a `.pfx` (PowerShell):

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("Wingnal.pfx")) | Set-Clipboard
```

The certificate's subject **must** match the manifest `Publisher` (`CN=micro`),
otherwise signing fails.

### No certificate configured (fallback)

If the secrets are absent, the workflow generates a throwaway self-signed
certificate each run and attaches `Wingnal.cer` to the release. To install a
package signed this way, a user must first import that `.cer` into
**Local Machine → Trusted People**, then double-click the `.msix`. Because a new
certificate is generated per release, this is fine for testing but not
recommended for distribution — configure a persistent certificate via the
secrets above for real releases.
