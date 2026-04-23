# KeyWallet

![Status](https://img.shields.io/badge/status-100%25-brightgreen)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Central API key storage. Store once, use everywhere.

## Features

- **Add/view/delete keys** — simple GUI
- **Masked display** — click eye to reveal
- **Quick copy** — one click copies to clipboard
- **Global hotkey** — `Ctrl+Shift+K` opens quick search from anywhere
- **System tray** — runs in background, always ready
- **Optional encryption** — set a master password to encrypt your keys
- **Importable** — other Python apps can read keys directly

## Quick Start

```bash
pip install -r requirements.txt
python main.py
```

## Usage

1. Click "+ Add Key"
2. Enter name (e.g., `anthropic`) and the API key
3. Key is stored in `~/.keywallet.json`

### Quick Search (Hotkey)

Press `Ctrl+Shift+K` anywhere:
1. Type key name (or partial match)
2. Press Enter
3. Key copied to clipboard

### Use in Other Apps

Just read the JSON directly:

```python
import json
from pathlib import Path

wallet = json.loads((Path.home() / ".keywallet.json").read_text())
key = wallet.get("anthropic")
```

Note: If wallet is encrypted, you'll need to decrypt it first (or just keep it unencrypted for dev convenience).

## Storage

Keys stored in `~/.keywallet.json`.

### Encryption (Optional)

On first launch, you'll be asked if you want to set a master password:
- **Set password** — keys encrypted with AES-256, prompts to unlock on open
- **Skip** — keys stored as plain JSON (fine for personal dev machine)

Toggle encryption anytime via ⚙ Settings.

Requires: `pip install cryptography`
