# Contributing to JerisLink

Thanks for your interest. JerisLink is a small project, so please keep changes focused.

1. Open an issue first for anything larger than a small fix, so we can agree on the approach.
2. Keep pull requests small and reviewable: one topic per PR.
3. Sign off every commit (Developer Certificate of Origin, https://developercertificate.org):
   `git commit -s`. By signing off you confirm you have the right to submit the change under the Apache License 2.0. There is no CLA.
4. Tests:
   - `support/`: `gofmt -l .` must print nothing; `go vet ./...` and `go test -race ./...` must pass.
   - `personal/mac-host/`: `swift build -c release` must succeed.
   - `personal/windows-client/`: the CMake Release build must succeed.
5. Never commit secrets, signing certificates, private keys, `.env` files, or real IP addresses and host names from your own network. Use placeholders such as `100.x.y.z` in docs and examples.
6. Logs attached to issues: remove IP addresses, host names and user names first.

Security problems: do not open a public issue; follow [SECURITY.md](SECURITY.md).
