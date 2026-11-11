# Release history

## v0.0.5

Bidirectional Unicode/plain-text clipboard synchronization.

Validated features:
- Windows -> macOS clipboard sync
- macOS -> Windows clipboard sync
- Unicode, Chinese text, emoji, and multiline text support within the 60 KiB text limit
- loop prevention when remote clipboard content is applied locally
- clipboard traffic isolated on a second MRC TCP session so keyboard/mouse control remains independent
- existing CPU/GDI renderer and Media Foundation decoder remain unchanged
- existing Windows Ctrl+A/C/V/Z, Windows+C, Windows+Space, Caps Lock/IME workflow, and mouse control remain compatible

Release artifact hashes are recorded in the frozen v0.0.5 release directory outside Git history.

## v0.0.4.2

First Git baseline for Jerislink.

Validated features:
- stable Windows CPU/GDI remote viewer
- branded self-contained Windows installer
- mouse and keyboard control
- Windows Ctrl+A/C/V/Z compatibility with macOS Command shortcuts
- Windows+C escape mapping to macOS Control+C
- Windows+Space mapping to macOS Control+Space for input-source switching
- Caps Lock support for English capitalization and temporary Chinese/English switching

The v0.0.4.2 release artifacts and checksums are stored outside Git history.
