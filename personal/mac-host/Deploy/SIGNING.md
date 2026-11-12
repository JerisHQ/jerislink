# JerisLink macOS signing

`build-apps.sh` signs the Input Helper first, then `JerisLink.app` (inside-out, no `--deep`), with hardened runtime (`--options runtime`) and `Deploy/JerisLink.entitlements`.

Both bundle identifiers stay fixed so macOS TCC recognizes upgraded builds:

- App: `org.jeris.jerislink.host`
- Input Helper: `org.jeris.jerislink.inputhelper`

## Signing modes

`build-apps.sh` picks the first mode that applies:

| Mode | Set by | Use |
|---|---|---|
| Developer ID | `JERISLINK_DEVELOPER_ID="Developer ID Application: <name> (<team id>)"`, optional `JERISLINK_SIGN_KEYCHAIN` | Release builds to share. Adds a secure timestamp. Notarize afterwards. |
| Local identity | default: `JerisLink Local Code Signing` in `~/Library/Keychains/JerisLinkSigning.keychain-db` | Builds for your own Mac. Stable TCC identity across rebuilds. |
| Ad-hoc | `JERISLINK_ALLOW_ADHOC=1` when the local identity is missing | CI and throwaway builds. Every build is a new TCC identity. |

Without one of these the build fails rather than silently producing an ad-hoc app.

## Entitlements

`JerisLink.entitlements` is empty on purpose. The app is not sandboxed, has no JIT and loads no third-party libraries, so the hardened runtime needs no exceptions. Screen Recording and Accessibility are TCC permissions the user grants; they are not entitlements. Add an entitlement only with a concrete failure that needs it.

## Local identity (own Mac)

Run once on the JerisLink Mac:

```sh
./Deploy/setup-local-signing.sh
```

- Certificate common name: `JerisLink Local Code Signing`
- Keychain: `~/Library/Keychains/JerisLinkSigning.keychain-db`
- Keychain password file: `~/Library/Application Support/JerisLink/signing/keychain.pass` (mode 0600)

The setup is idempotent. The certificate is self-signed; `codesign` embeds a designated requirement built from the certificate and the bundle identifier, which is what TCC records. `JERISLINK_SIGN_IDENTITY` and `JERISLINK_SIGN_KEYCHAIN` override the identity and keychain.

## Developer ID and notarization (release)

Local build:

```sh
JERISLINK_DEVELOPER_ID="Developer ID Application: <name> (<team id>)" ./Deploy/build-apps.sh out
JERISLINK_NOTARY_KEY_PATH=~/private/AuthKey_XXXX.p8 \
JERISLINK_NOTARY_KEY_ID=XXXX \
JERISLINK_NOTARY_ISSUER=<issuer uuid, team keys only> \
  ./Deploy/notarize.sh out/JerisLink.app out/JerisLink-macos.zip
```

`notarize.sh` submits with `xcrun notarytool` using an App Store Connect API key, waits, prints the notary log on failure, staples the ticket to the app, validates it, and zips the stapled app with `ditto`.

An API key is used instead of an Apple ID app-specific password: it can be revoked on its own, is not tied to a personal Apple ID login or 2FA, and works unattended in CI.

### GitHub release workflow

`.github/workflows/release.yml` (job `macos`) signs and notarizes only when these repository secrets are set. If any of the first four is missing, the job prints a warning and builds the unsigned (ad-hoc) zip instead; it does not fail.

| Secret | Content |
|---|---|
| `MACOS_DEVELOPER_ID_P12_BASE64` | base64 of the exported `.p12` (Developer ID Application certificate + private key) |
| `MACOS_DEVELOPER_ID_P12_PASSWORD` | the password set when exporting the `.p12` |
| `MACOS_NOTARY_KEY_P8_BASE64` | base64 of the App Store Connect API key file `AuthKey_<KEYID>.p8` |
| `MACOS_NOTARY_KEY_ID` | the API key's Key ID |
| `MACOS_NOTARY_ISSUER_ID` | the Issuer ID (team keys). Leave unset for an individual key. |

The workflow imports the `.p12` into a temporary keychain with a random password, signs, runs `verify-bundle.sh`, notarizes and staples, prints `codesign -dv`, `spctl -a -vv` and `xcrun stapler validate`, and deletes the keychain and key file at the end even if a step failed. The signed artifact is `JerisLink-<version>-macos-<arch>.zip`; the unsigned one ends in `-unsigned.zip`.

### Check a signed build

```sh
codesign -dv --verbose=2 JerisLink.app          # Authority=Developer ID Application ..., flags=0x10000(runtime)
codesign --verify --strict --deep --verbose=2 JerisLink.app
spctl -a -vv -t exec JerisLink.app              # accepted, source=Notarized Developer ID
xcrun stapler validate JerisLink.app            # The validate action worked!
```

## TCC and changing certificates

TCC stores the designated requirement, which includes the signing certificate. Any of these needs Screen Recording and Accessibility approved again:

- ad-hoc -> local identity,
- local identity -> Developer ID,
- a new or lost private key for the same certificate name.

Rebuilds with the same certificate and bundle identifiers keep their approvals. A Mac whose current apps are Developer ID signed stays on the same identity only with a Developer ID build from the same team; installing a local-identity or ad-hoc build there needs re-approval. Compare before deploying:

```sh
codesign -d -r- JerisLink.app
codesign -d -r- "JerisLink.app/Contents/Helpers/JerisLink Input Helper.app"
```

Do not replace the signing certificate casually.
