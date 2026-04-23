"""KeyWallet - Central API key storage."""

import os
import sys
import json
import base64
import hashlib
import threading
from pathlib import Path
from typing import Optional, Tuple
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import keyboard
    HAS_KEYBOARD = True
except ImportError:
    HAS_KEYBOARD = False

try:
    import pystray
    from PIL import Image, ImageDraw
    HAS_TRAY = True
except ImportError:
    HAS_TRAY = False

# === Theme: Gold on dark ===
COLORS = {
    "bg": "#1a1a1a",
    "surface": "#252525",
    "surface_hover": "#2f2f2f",
    "accent": "#fbbf24",
    "accent_hover": "#f59e0b",
    "accent_dim": "#d97706",
    "text": "#fafafa",
    "text_dim": "#a3a3a3",
    "border": "#404040",
    "success": "#22c55e",
    "error": "#ef4444",
}

WALLET_PATH = Path.home() / ".keywallet.json"
HOTKEY = "ctrl+shift+k"

# Encryption state (set after unlock)
_encryption_key: Optional[bytes] = None
_is_encrypted: bool = False


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def _encrypt_data(data: dict, password: str) -> dict:
    """Encrypt wallet data with password."""
    salt = os.urandom(16)
    key = _derive_key(password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(json.dumps(data).encode())
    return {
        "_encrypted": True,
        "_salt": base64.b64encode(salt).decode(),
        "_data": encrypted.decode()
    }


def _decrypt_data(encrypted: dict, password: str) -> Optional[dict]:
    """Decrypt wallet data. Returns None if wrong password."""
    try:
        salt = base64.b64decode(encrypted["_salt"])
        key = _derive_key(password, salt)
        f = Fernet(key)
        decrypted = f.decrypt(encrypted["_data"].encode())
        return json.loads(decrypted)
    except (InvalidToken, Exception):
        return None


def is_wallet_encrypted() -> bool:
    """Check if wallet file is encrypted."""
    if not WALLET_PATH.exists():
        return False
    try:
        data = json.loads(WALLET_PATH.read_text(encoding="utf-8"))
        return data.get("_encrypted", False)
    except:
        return False


def load_wallet_raw() -> dict:
    """Load raw wallet file (may be encrypted wrapper or plain keys)."""
    if WALLET_PATH.exists():
        try:
            return json.loads(WALLET_PATH.read_text(encoding="utf-8"))
        except:
            return {}
    return {}


def load_wallet() -> dict:
    """Load keys from wallet file."""
    global _is_encrypted
    if WALLET_PATH.exists():
        try:
            data = json.loads(WALLET_PATH.read_text(encoding="utf-8"))
            if data.get("_encrypted"):
                _is_encrypted = True
                # Need decryption key
                if _encryption_key:
                    decrypted = _decrypt_data(data, "")  # Key already derived
                    return decrypted if decrypted else {}
                return {}  # Locked
            return data
        except:
            return {}
    return {}


def save_wallet(data: dict, password: Optional[str] = None):
    """Save keys to wallet file, optionally encrypted."""
    global _is_encrypted
    if password is not None:
        # Encrypting
        encrypted = _encrypt_data(data, password)
        WALLET_PATH.write_text(json.dumps(encrypted, indent=2), encoding="utf-8")
        _is_encrypted = True
    elif _is_encrypted and _encryption_key:
        # Re-encrypt with existing password (stored in memory)
        # This requires passing password through, so we store it temporarily
        pass  # Handled by KeyWalletApp
    else:
        # Plain save
        WALLET_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def get_key(name: str) -> Optional[str]:
    """Get a key by name. For use by other apps."""
    if name.startswith("_"):  # Don't expose settings
        return None
    wallet = load_wallet()
    return wallet.get(name)


class KeyEntry(ctk.CTkFrame):
    """Single key entry row."""

    def __init__(self, parent, name: str, value: str, on_delete, on_copy, show_partial: bool = True):
        super().__init__(parent, fg_color=COLORS["surface"], corner_radius=8)

        self.name = name
        self.value = value
        self.revealed = False
        self.show_partial = show_partial

        # Name
        self.name_label = ctk.CTkLabel(
            self, text=name,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["accent"],
            width=120,
            anchor="w"
        )
        self.name_label.pack(side="left", padx=(15, 10), pady=12)

        # Value (masked)
        self.value_label = ctk.CTkLabel(
            self, text=self.masked_value(),
            font=ctk.CTkFont(size=12, family="Consolas"),
            text_color=COLORS["text_dim"],
            anchor="w"
        )
        self.value_label.pack(side="left", fill="x", expand=True, padx=5)

        # Reveal button
        self.reveal_btn = ctk.CTkButton(
            self, text="👁", width=32, height=32,
            fg_color="transparent",
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["text_dim"],
            command=self.toggle_reveal
        )
        self.reveal_btn.pack(side="right", padx=2)

        # Copy button
        copy_btn = ctk.CTkButton(
            self, text="📋", width=32, height=32,
            fg_color="transparent",
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["text_dim"],
            command=lambda: on_copy(name, value)
        )
        copy_btn.pack(side="right", padx=2)

        # Delete button
        del_btn = ctk.CTkButton(
            self, text="✕", width=32, height=32,
            fg_color="transparent",
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["text_dim"],
            command=lambda: on_delete(name)
        )
        del_btn.pack(side="right", padx=(2, 10))

    def masked_value(self) -> str:
        if not self.show_partial:
            # Full mask - just dots, capped length
            dots = min(len(self.value), 24)
            return "•" * dots + ("…" if len(self.value) > 24 else "")

        if len(self.value) <= 8:
            return "•" * len(self.value)
        # Show first 4, dots, last 4 — but cap total length for long keys
        middle_dots = min(len(self.value) - 8, 20)  # Cap at 20 dots
        display = self.value[:4] + "•" * middle_dots + self.value[-4:]
        if len(self.value) > 28:  # If we truncated
            display = self.value[:4] + "•" * 16 + "…" + self.value[-4:]
        return display

    def toggle_reveal(self):
        self.revealed = not self.revealed
        if self.revealed:
            self.value_label.configure(text=self.value)
            self.reveal_btn.configure(text="🙈")
        else:
            self.value_label.configure(text=self.masked_value())
            self.reveal_btn.configure(text="👁")


class PasswordDialog(ctk.CTkToplevel):
    """Dialog for entering or setting master password."""

    def __init__(self, parent, mode: str = "unlock", on_success=None):
        super().__init__(parent)

        self.mode = mode  # "unlock", "setup", "change"
        self.on_success = on_success
        self.result = None

        titles = {"unlock": "Unlock Wallet", "setup": "Set Master Password", "change": "Change Password"}
        self.title(titles.get(mode, "Password"))

        height = 320 if mode in ("setup", "change") else 200
        self.geometry(f"380x{height}")
        self.configure(fg_color=COLORS["bg"])
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.grab_set()

        # Center
        self.update_idletasks()
        x = (self.winfo_screenwidth() - 380) // 2
        y = (self.winfo_screenheight() - height) // 2
        self.geometry(f"380x{height}+{x}+{y}")

        self.setup_ui()
        self.focus_force()
        self.bind("<Escape>", lambda e: self.cancel())
        self.protocol("WM_DELETE_WINDOW", self.cancel)

    def setup_ui(self):
        if self.mode == "unlock":
            ctk.CTkLabel(
                self, text="🔒 Wallet is encrypted",
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color=COLORS["accent"]
            ).pack(pady=(20, 10))

            ctk.CTkLabel(
                self, text="Enter master password:",
                font=ctk.CTkFont(size=13),
                text_color=COLORS["text"]
            ).pack(anchor="w", padx=25, pady=(5, 5))

            self.password_entry = ctk.CTkEntry(
                self, fg_color=COLORS["surface"],
                text_color=COLORS["text"],
                border_color=COLORS["border"],
                show="•", width=330
            )
            self.password_entry.pack(padx=25)
            self.password_entry.focus()
            self.password_entry.bind("<Return>", lambda e: self.submit())

        elif self.mode == "setup":
            ctk.CTkLabel(
                self, text="🔐 Secure Your Wallet",
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color=COLORS["accent"]
            ).pack(pady=(20, 5))

            ctk.CTkLabel(
                self, text="Set a master password to encrypt your keys.\nLeave blank to keep wallet unencrypted.",
                font=ctk.CTkFont(size=12),
                text_color=COLORS["text_dim"]
            ).pack(pady=(0, 15))

            ctk.CTkLabel(
                self, text="Password:",
                font=ctk.CTkFont(size=13),
                text_color=COLORS["text"]
            ).pack(anchor="w", padx=25, pady=(5, 5))

            self.password_entry = ctk.CTkEntry(
                self, fg_color=COLORS["surface"],
                text_color=COLORS["text"],
                border_color=COLORS["border"],
                show="•", width=330
            )
            self.password_entry.pack(padx=25)
            self.password_entry.focus()

            ctk.CTkLabel(
                self, text="Confirm:",
                font=ctk.CTkFont(size=13),
                text_color=COLORS["text"]
            ).pack(anchor="w", padx=25, pady=(10, 5))

            self.confirm_entry = ctk.CTkEntry(
                self, fg_color=COLORS["surface"],
                text_color=COLORS["text"],
                border_color=COLORS["border"],
                show="•", width=330
            )
            self.confirm_entry.pack(padx=25)
            self.confirm_entry.bind("<Return>", lambda e: self.submit())

        # Buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=25, pady=20)

        if self.mode == "setup":
            ctk.CTkButton(
                btn_frame, text="Skip", width=80,
                fg_color=COLORS["surface"],
                hover_color=COLORS["surface_hover"],
                text_color=COLORS["text"],
                command=self.skip
            ).pack(side="left")
        else:
            ctk.CTkButton(
                btn_frame, text="Cancel", width=80,
                fg_color=COLORS["surface"],
                hover_color=COLORS["surface_hover"],
                text_color=COLORS["text"],
                command=self.cancel
            ).pack(side="left")

        ctk.CTkButton(
            btn_frame, text="Unlock" if self.mode == "unlock" else "Set Password",
            width=100,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color="#000000",
            command=self.submit
        ).pack(side="right")

        self.error_label = ctk.CTkLabel(
            self, text="",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["error"]
        )
        self.error_label.pack()

    def submit(self):
        password = self.password_entry.get()

        if self.mode == "setup":
            confirm = self.confirm_entry.get()
            if password and password != confirm:
                self.error_label.configure(text="Passwords don't match")
                self.confirm_entry.configure(border_color=COLORS["error"])
                return
            # Empty password = no encryption
            self.result = password if password else None
            if self.on_success:
                self.on_success(self.result)
            self.destroy()

        elif self.mode == "unlock":
            if not password:
                self.error_label.configure(text="Password required")
                return
            self.result = password
            if self.on_success:
                self.on_success(password)
            self.destroy()

    def skip(self):
        self.result = None
        if self.on_success:
            self.on_success(None)
        self.destroy()

    def cancel(self):
        self.result = False  # Distinguishes from skip (None)
        self.destroy()


class AddKeyDialog(ctk.CTkToplevel):
    """Dialog to add a new key."""

    def __init__(self, parent, on_save, existing_names: list):
        super().__init__(parent)

        self.on_save = on_save
        self.existing_names = existing_names

        self.title("Add Key")
        self.geometry("400x220")
        self.configure(fg_color=COLORS["bg"])
        self.resizable(False, False)
        self.attributes("-topmost", True)

        # Center
        self.update_idletasks()
        x = (self.winfo_screenwidth() - 400) // 2
        y = (self.winfo_screenheight() - 220) // 2
        self.geometry(f"400x220+{x}+{y}")

        self.setup_ui()
        self.focus_force()
        self.bind("<Escape>", lambda e: self.destroy())

    def setup_ui(self):
        # Name
        ctk.CTkLabel(
            self, text="Key Name:",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text"]
        ).pack(anchor="w", padx=20, pady=(20, 5))

        self.name_entry = ctk.CTkEntry(
            self, fg_color=COLORS["surface"],
            text_color=COLORS["text"],
            border_color=COLORS["border"],
            placeholder_text="e.g. anthropic, openai, github"
        )
        self.name_entry.pack(fill="x", padx=20)
        self.name_entry.focus()

        # Value
        ctk.CTkLabel(
            self, text="API Key:",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["text"]
        ).pack(anchor="w", padx=20, pady=(15, 5))

        self.value_entry = ctk.CTkEntry(
            self, fg_color=COLORS["surface"],
            text_color=COLORS["text"],
            border_color=COLORS["border"],
            placeholder_text="sk-...",
            show="•"
        )
        self.value_entry.pack(fill="x", padx=20)

        # Buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=20)

        ctk.CTkButton(
            btn_frame, text="Cancel", width=80,
            fg_color=COLORS["surface"],
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["text"],
            command=self.destroy
        ).pack(side="left")

        ctk.CTkButton(
            btn_frame, text="Save", width=80,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color="#000000",
            command=self.save
        ).pack(side="right")

        self.bind("<Return>", lambda e: self.save())

    def save(self):
        name = self.name_entry.get().strip().lower()
        value = self.value_entry.get().strip()

        if not name:
            self.name_entry.configure(border_color=COLORS["error"])
            return
        if not value:
            self.value_entry.configure(border_color=COLORS["error"])
            return
        if name in self.existing_names:
            self.name_entry.configure(border_color=COLORS["error"])
            return

        self.on_save(name, value)
        self.destroy()


class KeyWalletApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("KeyWallet")
        self.geometry("560x450")
        self.configure(fg_color=COLORS["bg"])
        self.minsize(500, 350)

        self.wallet = {}
        self.tray_icon = None
        self.search_window = None
        self.master_password = None  # Stored for re-encryption on save
        self.is_encrypted = False
        self.is_locked = False  # Manual lock state
        self.show_partial = True  # Show first/last 4 chars, or full mask

        self.setup_ui()
        self.setup_hotkey()
        self.setup_tray()

        self.protocol("WM_DELETE_WINDOW", self.minimize_to_tray)

        # Check encryption state and load wallet
        self.after(100, self.check_wallet_state)

    def check_wallet_state(self):
        """Check if wallet exists/encrypted and handle accordingly."""
        if not WALLET_PATH.exists():
            # First run - offer to set up encryption
            if HAS_CRYPTO:
                self.show_setup_dialog()
            else:
                self.wallet = {}
                self.refresh_list()
        elif is_wallet_encrypted():
            if HAS_CRYPTO:
                self.show_unlock_dialog()
            else:
                messagebox.showerror("Error", "Wallet is encrypted but cryptography module not installed.\npip install cryptography")
                self.quit_app()
        else:
            self.wallet = load_wallet_raw()
            self.show_partial = self.wallet.get("_show_partial", True)
            self.refresh_list()

    def show_setup_dialog(self):
        """First-run setup dialog."""
        def on_setup(password):
            self.master_password = password
            self.is_encrypted = password is not None
            self.wallet = {}
            if self.is_encrypted:
                self.save_encrypted()
            self.refresh_list()

        PasswordDialog(self, mode="setup", on_success=on_setup)

    def show_unlock_dialog(self):
        """Prompt for password to unlock encrypted wallet."""
        def try_unlock(password):
            raw = load_wallet_raw()
            decrypted = _decrypt_data(raw, password)
            if decrypted is not None:
                self.wallet = decrypted
                self.master_password = password
                self.is_encrypted = True
                self.show_partial = self.wallet.get("_show_partial", True)
                self.refresh_list()
            else:
                messagebox.showerror("Wrong Password", "Incorrect master password.")
                self.show_unlock_dialog()

        dialog = PasswordDialog(self, mode="unlock", on_success=try_unlock)
        dialog.wait_window()
        if dialog.result is False:  # Cancelled
            self.quit_app()

    def save_encrypted(self):
        """Save wallet with encryption."""
        if self.is_encrypted and self.master_password:
            encrypted = _encrypt_data(self.wallet, self.master_password)
            WALLET_PATH.write_text(json.dumps(encrypted, indent=2), encoding="utf-8")
        else:
            WALLET_PATH.write_text(json.dumps(self.wallet, indent=2), encoding="utf-8")

    def save_wallet_data(self):
        """Save wallet (handles encryption automatically)."""
        self.save_encrypted()

    def setup_ui(self):
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))

        ctk.CTkLabel(
            header, text="🔑 KeyWallet",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=COLORS["accent"]
        ).pack(side="left")

        # Add button
        add_btn = ctk.CTkButton(
            header, text="+ Add Key", width=100, height=32,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color="#000000",
            command=self.show_add_dialog
        )
        add_btn.pack(side="right")

        # Help button
        help_btn = ctk.CTkButton(
            header, text="?", width=32, height=32,
            fg_color=COLORS["surface"],
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["text_dim"],
            font=ctk.CTkFont(size=16, weight="bold"),
            command=self.show_help
        )
        help_btn.pack(side="right", padx=(0, 5))

        # Lock button (only useful when encrypted)
        self.lock_btn = ctk.CTkButton(
            header, text="🔒", width=32, height=32,
            fg_color=COLORS["surface"],
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["text_dim"],
            command=self.lock_wallet
        )
        self.lock_btn.pack(side="right", padx=(0, 5))

        # Settings button
        settings_btn = ctk.CTkButton(
            header, text="⚙", width=32, height=32,
            fg_color=COLORS["surface"],
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["text_dim"],
            command=self.show_settings
        )
        settings_btn.pack(side="right", padx=(0, 5))

        # Key list
        self.list_frame = ctk.CTkScrollableFrame(
            self, fg_color=COLORS["surface"], corner_radius=12,
            scrollbar_button_color=COLORS["accent_dim"],
            scrollbar_button_hover_color=COLORS["accent"]
        )
        self.list_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # Footer
        self.footer = ctk.CTkFrame(self, fg_color="transparent")
        self.footer.pack(fill="x", padx=20, pady=(0, 15))

        ctk.CTkLabel(
            self.footer, text=f"Hotkey: {HOTKEY.upper()} to quick-search",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"]
        ).pack(side="left")

        self.status_label = ctk.CTkLabel(
            self.footer, text="",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["text_dim"]
        )
        self.status_label.pack(side="right")

    def refresh_list(self):
        """Refresh the key list display."""
        for widget in self.list_frame.winfo_children():
            widget.destroy()

        # Update footer status and lock button visibility
        if self.is_locked:
            self.status_label.configure(text="🔒 Locked", text_color=COLORS["accent_dim"])
            self.lock_btn.configure(state="disabled", text_color=COLORS["text_dim"])
        elif self.is_encrypted:
            self.status_label.configure(text="🔒 Encrypted", text_color=COLORS["success"])
            self.lock_btn.configure(state="normal", text_color=COLORS["accent"])
        else:
            self.status_label.configure(text="🔓 Unencrypted", text_color=COLORS["text_dim"])
            self.lock_btn.configure(state="normal", text_color=COLORS["text_dim"])

        # Show locked screen
        if self.is_locked:
            locked_frame = ctk.CTkFrame(self.list_frame, fg_color="transparent")
            locked_frame.pack(expand=True, pady=50)

            ctk.CTkLabel(
                locked_frame, text="🔒",
                font=ctk.CTkFont(size=48),
                text_color=COLORS["text_dim"]
            ).pack(pady=(0, 10))

            ctk.CTkLabel(
                locked_frame, text="Wallet is locked",
                font=ctk.CTkFont(size=16),
                text_color=COLORS["text_dim"]
            ).pack(pady=(0, 15))

            ctk.CTkButton(
                locked_frame, text="Unlock", width=100, height=36,
                fg_color=COLORS["accent"],
                hover_color=COLORS["accent_hover"],
                text_color="#000000",
                command=self.unlock_wallet
            ).pack()
            return

        if not self.wallet:
            empty = ctk.CTkLabel(
                self.list_frame,
                text="No keys stored yet\n\nClick '+ Add Key' to add your first API key",
                font=ctk.CTkFont(size=14),
                text_color=COLORS["text_dim"]
            )
            empty.pack(expand=True, pady=50)
            return

        for name in sorted(self.wallet.keys()):
            if name.startswith("_"):  # Skip settings keys
                continue
            entry = KeyEntry(
                self.list_frame, name, self.wallet[name],
                on_delete=self.delete_key,
                on_copy=self.copy_key,
                show_partial=self.show_partial
            )
            entry.pack(fill="x", pady=4, padx=5)

    def show_add_dialog(self):
        if self.is_locked:
            return
        AddKeyDialog(self, self.add_key, list(self.wallet.keys()))

    def show_help(self):
        """Show help dialog."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("How to Use")
        dialog.geometry("420x540")
        dialog.configure(fg_color=COLORS["bg"])
        dialog.resizable(False, False)
        dialog.attributes("-topmost", True)

        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - 420) // 2
        y = (dialog.winfo_screenheight() - 540) // 2
        dialog.geometry(f"420x540+{x}+{y}")

        ctk.CTkLabel(
            dialog, text="🔑 KeyWallet",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=COLORS["accent"]
        ).pack(pady=(20, 10))

        help_text = """Store your API keys in one place, use them everywhere.

BASICS
• Click "+ Add Key" to store a new key
• Give it a name (e.g., "anthropic", "openai")
• Keys are masked by default — click 👁 to reveal

QUICK ACCESS
• Press Ctrl+Shift+K from anywhere
• Type part of the key name, hit Enter
• Key is copied to your clipboard

USE IN YOUR CODE
  import json
  from pathlib import Path
  wallet = json.loads(
      (Path.home() / ".keywallet.json").read_text()
  )
  key = wallet.get("anthropic")

SECURITY
• Optional master password encrypts all keys
• Set via ⚙ Settings → Enable encryption
• Without password, keys stored as plain JSON"""

        text_frame = ctk.CTkFrame(dialog, fg_color=COLORS["surface"], corner_radius=8)
        text_frame.pack(fill="both", expand=True, padx=20, pady=10)

        help_textbox = ctk.CTkTextbox(
            text_frame,
            font=ctk.CTkFont(size=12, family="Consolas"),
            text_color=COLORS["text"],
            fg_color=COLORS["surface"],
            wrap="word",
            activate_scrollbars=False
        )
        help_textbox.pack(fill="both", expand=True, padx=10, pady=10)
        help_textbox.insert("1.0", help_text)
        help_textbox.configure(state="disabled")  # Read-only but still selectable

        ctk.CTkButton(
            dialog, text="Got it", width=80,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_hover"],
            text_color="#000000",
            command=dialog.destroy
        ).pack(pady=15)

        dialog.bind("<Escape>", lambda e: dialog.destroy())

    def show_settings(self):
        """Show settings dialog."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Settings")
        dialog.geometry("350x280")
        dialog.configure(fg_color=COLORS["bg"])
        dialog.resizable(False, False)
        dialog.attributes("-topmost", True)
        dialog.grab_set()

        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - 350) // 2
        y = (dialog.winfo_screenheight() - 280) // 2
        dialog.geometry(f"350x280+{x}+{y}")

        ctk.CTkLabel(
            dialog, text="⚙ Settings",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=COLORS["accent"]
        ).pack(pady=(20, 15))

        # Encryption toggle
        enc_frame = ctk.CTkFrame(dialog, fg_color=COLORS["surface"], corner_radius=8)
        enc_frame.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(
            enc_frame, text="🔐 Encryption",
            font=ctk.CTkFont(size=14),
            text_color=COLORS["text"]
        ).pack(side="left", padx=15, pady=12)

        status = "Enabled" if self.is_encrypted else "Disabled"
        status_color = COLORS["success"] if self.is_encrypted else COLORS["text_dim"]

        ctk.CTkLabel(
            enc_frame, text=status,
            font=ctk.CTkFont(size=12),
            text_color=status_color
        ).pack(side="left", padx=5)

        btn_text = "Disable" if self.is_encrypted else "Enable"

        def toggle_encryption():
            if not HAS_CRYPTO:
                messagebox.showerror("Error", "Install cryptography module:\npip install cryptography")
                return

            if self.is_encrypted:
                # Disable encryption
                if messagebox.askyesno("Disable Encryption", "Remove password protection?\nKeys will be stored in plain text."):
                    self.is_encrypted = False
                    self.master_password = None
                    self.save_wallet_data()
                    dialog.destroy()
                    self.show_settings()
            else:
                # Enable encryption
                def on_set(password):
                    if password:
                        self.master_password = password
                        self.is_encrypted = True
                        self.save_wallet_data()
                        dialog.destroy()
                        self.show_settings()

                dialog.destroy()
                PasswordDialog(self, mode="setup", on_success=on_set)

        ctk.CTkButton(
            enc_frame, text=btn_text, width=70, height=28,
            fg_color=COLORS["accent_dim"],
            hover_color=COLORS["accent"],
            text_color="#000000",
            command=toggle_encryption
        ).pack(side="right", padx=15, pady=8)

        # Masking style toggle
        mask_frame = ctk.CTkFrame(dialog, fg_color=COLORS["surface"], corner_radius=8)
        mask_frame.pack(fill="x", padx=20, pady=5)

        ctk.CTkLabel(
            mask_frame, text="👁 Key Display",
            font=ctk.CTkFont(size=14),
            text_color=COLORS["text"]
        ).pack(side="left", padx=15, pady=12)

        mask_status = "Partial" if self.show_partial else "Full mask"

        ctk.CTkLabel(
            mask_frame, text=mask_status,
            font=ctk.CTkFont(size=12),
            text_color=COLORS["text_dim"]
        ).pack(side="left", padx=5)

        def toggle_masking():
            self.show_partial = not self.show_partial
            self.wallet["_show_partial"] = self.show_partial
            self.save_wallet_data()
            self.refresh_list()
            dialog.destroy()
            self.show_settings()

        mask_btn_text = "Full mask" if self.show_partial else "Show partial"
        ctk.CTkButton(
            mask_frame, text=mask_btn_text, width=85, height=28,
            fg_color=COLORS["accent_dim"],
            hover_color=COLORS["accent"],
            text_color="#000000",
            command=toggle_masking
        ).pack(side="right", padx=15, pady=8)

        # Close button
        ctk.CTkButton(
            dialog, text="Close", width=80,
            fg_color=COLORS["surface"],
            hover_color=COLORS["surface_hover"],
            text_color=COLORS["text"],
            command=dialog.destroy
        ).pack(pady=20)

    def lock_wallet(self):
        """Manually lock the wallet."""
        if not self.is_encrypted:
            messagebox.showinfo("Not Encrypted", "Wallet is not encrypted.\nEnable encryption in Settings to use lock.")
            return

        self.is_locked = True
        self.refresh_list()

    def unlock_wallet(self):
        """Prompt to unlock after manual lock."""
        def try_unlock(password):
            if password == self.master_password:
                self.is_locked = False
                self.refresh_list()
            else:
                messagebox.showerror("Wrong Password", "Incorrect master password.")
                self.unlock_wallet()

        dialog = PasswordDialog(self, mode="unlock", on_success=try_unlock)

    def add_key(self, name: str, value: str):
        self.wallet[name] = value
        self.save_wallet_data()
        self.refresh_list()

    def delete_key(self, name: str):
        if name in self.wallet:
            del self.wallet[name]
            self.save_wallet_data()
            self.refresh_list()

    def copy_key(self, name: str, value: str):
        self.clipboard_clear()
        self.clipboard_append(value)
        self.show_notification("Copied!", f"{name} key copied to clipboard")

    def setup_hotkey(self):
        if not HAS_KEYBOARD:
            return
        try:
            keyboard.add_hotkey(HOTKEY, self.show_search)
        except:
            pass

    def show_search(self):
        """Show quick search popup."""
        self.after(0, self._show_search_window)

    def _show_search_window(self):
        # Don't allow search when locked
        if self.is_locked:
            self.show_notification("Locked", "Unlock wallet first")
            return

        # Toggle: if already open, close it
        if self.search_window and self.search_window.winfo_exists():
            self.search_window.destroy()
            self.search_window = None
            return

        self.search_window = ctk.CTkToplevel(self)
        self.search_window.title("Quick Key Search")
        self.search_window.geometry("350x60")
        self.search_window.configure(fg_color=COLORS["bg"])
        self.search_window.attributes("-topmost", True)
        self.search_window.overrideredirect(True)

        # Center
        self.search_window.update_idletasks()
        x = (self.search_window.winfo_screenwidth() - 350) // 2
        y = (self.search_window.winfo_screenheight() - 60) // 2 - 100
        self.search_window.geometry(f"350x60+{x}+{y}")

        frame = ctk.CTkFrame(self.search_window, fg_color=COLORS["surface"], corner_radius=12)
        frame.pack(fill="both", expand=True, padx=2, pady=2)

        self.search_entry = ctk.CTkEntry(
            frame,
            fg_color=COLORS["bg"],
            text_color=COLORS["text"],
            border_color=COLORS["accent"],
            border_width=2,
            placeholder_text="Type key name...",
            font=ctk.CTkFont(size=16),
            height=40
        )
        self.search_entry.pack(fill="x", padx=10, pady=10)
        self.search_entry.focus()

        def close_search(e=None):
            if self.search_window:
                self.search_window.destroy()
                self.search_window = None

        self.search_entry.bind("<Return>", self._search_and_copy)
        self.search_entry.bind("<Escape>", close_search)
        self.search_window.bind("<FocusOut>", close_search)

    def _search_and_copy(self, event):
        query = self.search_entry.get().strip().lower()
        if not query:
            self.search_window.destroy()
            return

        # Find matching key
        matches = [k for k in self.wallet.keys() if query in k.lower()]

        if len(matches) == 1:
            key_name = matches[0]
            self.clipboard_clear()
            self.clipboard_append(self.wallet[key_name])
            self.show_notification("Copied!", f"{key_name}")
        elif len(matches) > 1:
            # Copy first match
            key_name = matches[0]
            self.clipboard_clear()
            self.clipboard_append(self.wallet[key_name])
            self.show_notification("Copied!", f"{key_name} (first of {len(matches)} matches)")
        else:
            self.show_notification("Not found", f"No key matching '{query}'")

        self.search_window.destroy()

    def setup_tray(self):
        if not HAS_TRAY:
            return

        # Gold key icon
        icon_size = 64
        icon_img = Image.new('RGBA', (icon_size, icon_size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(icon_img)
        draw.ellipse([16, 16, 48, 48], fill=COLORS["accent"])

        menu = pystray.Menu(
            pystray.MenuItem("Show", self.show_from_tray),
            pystray.MenuItem(f"Quick Search ({HOTKEY.upper()})", lambda: self.after(0, self._show_search_window)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self.quit_app)
        )

        self.tray_icon = pystray.Icon("keywallet", icon_img, "KeyWallet", menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def show_notification(self, title: str, message: str):
        if self.tray_icon:
            try:
                self.tray_icon.notify(message, title)
            except:
                pass

    def minimize_to_tray(self):
        if HAS_TRAY and self.tray_icon:
            self.withdraw()
        else:
            self.quit_app()

    def show_from_tray(self):
        self.after(0, self._show_window)

    def _show_window(self):
        self.deiconify()
        self.lift()
        self.focus_force()

    def quit_app(self):
        if HAS_KEYBOARD:
            try:
                keyboard.unhook_all()
            except:
                pass
        if self.tray_icon:
            self.tray_icon.stop()
        self.destroy()
        sys.exit(0)


# === For importing by other apps ===
def get_api_key(name: str) -> Optional[str]:
    """Get an API key by name. Returns None if not found."""
    return get_key(name)


def main():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")

    app = KeyWalletApp()
    app.mainloop()


if __name__ == "__main__":
    main()
