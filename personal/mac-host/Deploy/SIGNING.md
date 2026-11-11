# JerisLink macOS signing

JerisLink Host and JerisLink Input Helper must use a stable code-signing identity so macOS TCC can recognize upgraded builds as the same applications.

## Production identity

- Certificate common name: `JerisLink Local Code Signing`
- Keychain: `~/Library/Keychains/JerisLinkSigning.keychain-db`
- Keychain password file: `~/Library/Application Support/JerisLink/signing/keychain.pass` (mode 0600)
- Host bundle identifier: `org.jeris.jerislink.host`
- Input Helper bundle identifier: `org.jeris.jerislink.inputhelper`

The certificate is local/self-signed and is intended for JerisLink on the developer's own Mac. Its private key lives in the dedicated JerisLink signing Keychain. The certificate does not need to be Apple-issued for local code identity; `codesign` embeds a stable designated requirement based on the certificate root fingerprint plus the bundle identifier.

## Setup

On the JerisLink Mac, run once:

```sh
./Deploy/setup-local-signing.sh
```

The setup is idempotent: it reuses an existing JerisLink signing keychain/certificate and refreshes the non-interactive `codesign` key partition ACL. On a new Mac it creates a new local identity, which necessarily becomes a new TCC identity and requires one-time approval.

## Build behavior

`build-apps.sh` requires the stable identity by default. It unlocks the dedicated signing keychain and intentionally fails instead of silently producing a new ad-hoc identity.

For disposable development builds only, ad-hoc signing can be explicitly enabled:

```sh
JERISLINK_ALLOW_ADHOC=1 ./Deploy/build-apps.sh
```

The identity and keychain can be overridden with `JERISLINK_SIGN_IDENTITY` and `JERISLINK_SIGN_KEYCHAIN`.

## TCC migration

The existing production apps were previously ad-hoc signed, so the first migration to the stable certificate changes their designated requirements. Screen Recording for JerisLink Host and Accessibility for JerisLink Input Helper therefore require one final approval after the signed production apps are installed. Subsequent rebuilds signed with the same certificate and bundle identifiers should retain the same code identity.

Before production deployment, compare designated requirements with:

```sh
codesign -d -r- "JerisLink Host.app"
codesign -d -r- "JerisLink Input Helper.app"
```

Do not replace the signing certificate casually. Losing or replacing its private key changes the code identity and requires TCC approval again.
