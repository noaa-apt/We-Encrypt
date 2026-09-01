import base64
import hashlib
import os
import secrets
import string
import sys
import textwrap
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

KDF_ITERATIONS = 200_000
SALT_LEN = 16
NONCE_LEN = 12
LOCKOUT_SECONDS = 60
MAX_ATTEMPTS = 5

APP_BG = "#1e1f26"
PANEL_BG = "#262832"
FIELD_BG = "#12131a"
ACCENT = "#7c5cff"
ACCENT_HOVER = "#9376ff"
FG = "#e8e8f0"
MUTED = "#9a9aab"
DANGER = "#ff5c7a"
OK_COLOR = "#5cffa0"

PERM_START = "# --- WE_ENCRYPT_PERM_BLOB_START ---"
PERM_END = "# --- WE_ENCRYPT_PERM_BLOB_END ---"

def derive_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """Returns salt || nonce || ciphertext(+tag), AES-256-GCM."""
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return salt + nonce + ct


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """Raises on wrong password / corrupted data."""
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN + NONCE_LEN]
    ct = blob[SALT_LEN + NONCE_LEN:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def password_check_hash(password: str, salt: bytes) -> str:
    """A separate, independent hash."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000).hex()


def random_identifier(n: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def extract_perm_blob(locked_path: str) -> bytes:
    with open(locked_path, "r", encoding="utf-8") as f:
        content = f.read()
    if PERM_START not in content or PERM_END not in content:
        raise ValueError("This does not look like a We Encrypt locked file.")
    section = content.split(PERM_START, 1)[1].split(PERM_END, 1)[0]
    b64_lines = [
        line.strip()[1:].strip()
        for line in section.splitlines()
        if line.strip().startswith("#")
    ]
    return base64.b64decode("".join(b64_lines))

RUNTIME_TEMPLATE = '''\
# ============================================================
# Protected by We Encrypt. Do not edit this header by hand.

# Go to www.github.com/noaa-apt/we-encrypt, download the file, and choose to decrypt.
# ============================================================
import sys, os, time, hashlib, secrets

_WE_BLOB = {blob!r}
_WE_RUN_KEY = {run_key!r}
_WE_PERM_BLOB = {perm_blob!r}
_WE_CHECK_SALT = {check_salt!r}
_WE_CHECK_HASH = {check_hash!r}
_WE_MAX_ATTEMPTS = {max_attempts}
_WE_LOCKOUT_SECONDS = {lockout_seconds}
_WE_ORIG_NAME = {orig_name!r}
_WE_LOCKOUT_FILE = os.path.join(
    os.path.expanduser("~"), ".we_encrypt_lockout_{lockout_id}"
)


def _we_self_path():
    try:
        return os.path.abspath(__file__)
    except NameError:
        return os.path.abspath(sys.argv[0])


def _we_derive(password, salt, iterations=200000):
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


def _we_decrypt(blob, password):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = blob[:16]
    nonce = blob[16:28]
    ct = blob[28:]
    key = _we_derive(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def _we_run_normally():
    """Executes the original program. Never touches the password-protected
    blob or asks for anything -- this is the default, no-flag behavior."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = _WE_BLOB[:16]
    nonce = _WE_BLOB[16:28]
    ct = _WE_BLOB[28:]
    key = _we_derive(_WE_RUN_KEY, salt)
    aesgcm = AESGCM(key)
    src = aesgcm.decrypt(nonce, ct, None)
    code_obj = compile(src, _WE_ORIG_NAME, "exec")
    g = {{"__name__": "__main__", "__file__": _WE_ORIG_NAME}}
    exec(code_obj, g)


def _we_remaining_lockout():
    if os.path.exists(_WE_LOCKOUT_FILE):
        try:
            until = float(open(_WE_LOCKOUT_FILE).read().strip())
        except Exception:
            until = 0
        remaining = until - time.time()
        if remaining > 0:
            return remaining
        try:
            os.remove(_WE_LOCKOUT_FILE)
        except OSError:
            pass
    return 0


def _we_trigger_lockout():
    until = time.time() + _WE_LOCKOUT_SECONDS
    try:
        with open(_WE_LOCKOUT_FILE, "w") as f:
            f.write(str(until))
    except OSError:
        pass


def _we_restore_self(plaintext_bytes):
    """Permanently rewrites THIS file in place back to plain source.
    Source is never printed to a terminal or shown in a window."""
    path = _we_self_path()
    with open(path, "wb") as f:
        f.write(plaintext_bytes)


def _we_decrypt_gui():
    """The -dc window: verifies the password, then rewrites this file
    in place. Never prints or displays the decrypted source."""
    import tkinter as tk
    from tkinter import messagebox

    root = tk.Tk()
    root.title("We Encrypt -- Unlock")
    root.configure(bg="#1e1f26")
    root.geometry("420x230")
    root.resizable(False, False)

    state = {{"attempts": 0}}

    frame = tk.Frame(root, bg="#1e1f26")
    frame.pack(expand=True, fill="both", padx=24, pady=24)

    tk.Label(frame, text="Enter password to unlock this file", bg="#1e1f26",
             fg="#e8e8f0", font=("Segoe UI", 12, "bold")).pack(anchor="w")

    status_var = tk.StringVar(value="")
    tk.Label(frame, textvariable=status_var, bg="#1e1f26", fg="#ff5c7a",
              font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 8))

    pw_var = tk.StringVar()
    pw_entry = tk.Entry(frame, textvariable=pw_var, show="*", width=34,
                         bg="#12131a", fg="#e8e8f0", insertbackground="#e8e8f0",
                         relief="flat")
    pw_entry.pack(fill="x", ipady=6)
    pw_entry.focus_set()

    btn_row = tk.Frame(frame, bg="#1e1f26")
    btn_row.pack(fill="x", pady=(16, 0))

    def lock_ui_for(seconds):
        pw_entry.config(state="disabled")
        submit_btn.config(state="disabled")

        def tick(remaining):
            if remaining <= 0:
                status_var.set("")
                pw_entry.config(state="normal")
                submit_btn.config(state="normal")
                pw_entry.focus_set()
                return
            status_var.set("Locked out. Try again in {{}}s.".format(int(remaining)))
            root.after(1000, tick, remaining - 1)

        tick(seconds)

    def attempt(event=None):
        remaining = _we_remaining_lockout()
        if remaining > 0:
            lock_ui_for(remaining)
            return
        pw = pw_var.get()
        test_hash = hashlib.pbkdf2_hmac(
            "sha256", pw.encode("utf-8"), _WE_CHECK_SALT, 100000
        ).hex()
        if secrets.compare_digest(test_hash, _WE_CHECK_HASH):
            try:
                plaintext = _we_decrypt(_WE_PERM_BLOB, pw)
            except Exception:
                messagebox.showerror("We Encrypt", "Decryption failed (corrupted data).")
                root.destroy()
                return
            try:
                _we_restore_self(plaintext)
            except OSError as e:
                messagebox.showerror("We Encrypt", "Could not write file: {{}}".format(e))
                root.destroy()
                return
            root.destroy()
            done = tk.Tk()
            done.title("We Encrypt")
            done.configure(bg="#1e1f26")
            done.geometry("380x140")
            done.resizable(False, False)
            tk.Label(done, text="Unlocked.", bg="#1e1f26", fg="#5cffa0",
                     font=("Segoe UI", 12, "bold")).pack(pady=(24, 6))
            tk.Label(done, text="This file has been permanently restored\\nto plain source.",
                     bg="#1e1f26", fg="#e8e8f0", font=("Segoe UI", 9)).pack()
            tk.Button(done, text="OK", command=done.destroy, bg="#7c5cff", fg="white",
                      relief="flat", padx=16, pady=6, cursor="hand2").pack(pady=16)
            done.mainloop()
            return
        state["attempts"] += 1
        pw_var.set("")
        remaining_attempts = _WE_MAX_ATTEMPTS - state["attempts"]
        if remaining_attempts > 0:
            status_var.set("Incorrect password. {{}} attempt(s) left.".format(remaining_attempts))
        else:
            _we_trigger_lockout()
            lock_ui_for(_WE_LOCKOUT_SECONDS)

    submit_btn = tk.Button(btn_row, text="Unlock", command=attempt,
                            bg="#7c5cff", fg="white", relief="flat",
                            activebackground="#9376ff", font=("Segoe UI", 10, "bold"),
                            padx=16, pady=6, cursor="hand2")
    submit_btn.pack(side="right")
    pw_entry.bind("<Return>", attempt)

    initial_remaining = _we_remaining_lockout()
    if initial_remaining > 0:
        lock_ui_for(initial_remaining)

    root.mainloop()


if __name__ == "__main__":
    if "-dc" in sys.argv:
        _we_decrypt_gui()
    else:
        _we_run_normally()
'''

class WeEncryptError(Exception):
    pass


def encrypt_file(path: str, password: str) -> None:
    """Rewrites `path` in place into a locked, self-running .py file."""
    if not path.endswith(".py"):
        raise WeEncryptError("We Encrypt only works on .py files.")
    if not os.path.isfile(path):
        raise WeEncryptError(f"File not found: {path}")
    if not password:
        raise WeEncryptError("Password cannot be empty.")

    with open(path, "rb") as f:
        plaintext = f.read()

    try:
        compile(plaintext, path, "exec")
    except SyntaxError as e:
        raise WeEncryptError(f"File has a syntax error, refusing to encrypt: {e}")
    perm_blob = encrypt_bytes(plaintext, password)
    run_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    run_blob = encrypt_bytes(plaintext, run_key)

    check_salt = secrets.token_bytes(16)
    check_hash = password_check_hash(password, check_salt)

    lockout_id = random_identifier(10)
    orig_name = os.path.basename(path)

    rendered = RUNTIME_TEMPLATE.format(
        blob=run_blob,
        run_key=run_key,
        perm_blob=perm_blob,
        check_salt=check_salt,
        check_hash=check_hash,
        max_attempts=MAX_ATTEMPTS,
        lockout_seconds=LOCKOUT_SECONDS,
        orig_name=orig_name,
        lockout_id=lockout_id,
    )

    perm_b64 = base64.b64encode(perm_blob).decode("ascii")
    wrapped = "\n".join(textwrap.wrap(perm_b64, 76))
    perm_section = (
        f"\n{PERM_START}\n"
        + "\n".join(f"# {line}" for line in wrapped.splitlines())
        + f"\n{PERM_END}\n"
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(rendered)
        f.write(perm_section)


def decrypt_file(path: str, password: str) -> None:
    """Rewrites a locked `path` in place back into plain source. Requires
    the correct password. This never prints or returns the source -- it
    is only ever written back to the file itself."""
    if not os.path.isfile(path):
        raise WeEncryptError(f"File not found: {path}")
    try:
        blob = extract_perm_blob(path)
    except ValueError as e:
        raise WeEncryptError(str(e))

    try:
        plaintext = decrypt_bytes(blob, password)
    except Exception:
        raise WeEncryptError("Incorrect password, or file is corrupted.")

    with open(path, "wb") as f:
        f.write(plaintext)
class WeEncryptApp:
    def __init__(self, root):
        self.root = root
        root.title("We Encrypt")
        root.configure(bg=APP_BG)
        root.geometry("560x520")
        root.minsize(520, 480)

        self._build_style()
        self._build_header()

        self.notebook = ttk.Notebook(root, style="We.TNotebook")
        self.notebook.pack(expand=True, fill="both", padx=20, pady=(10, 20))

        self.encrypt_tab = tk.Frame(self.notebook, bg=PANEL_BG)
        self.decrypt_tab = tk.Frame(self.notebook, bg=PANEL_BG)
        self.notebook.add(self.encrypt_tab, text="  Encrypt a file  ")
        self.notebook.add(self.decrypt_tab, text="  Decrypt a file  ")

        self._build_encrypt_tab()
        self._build_decrypt_tab()
    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("We.TNotebook", background=APP_BG, borderwidth=0)
        style.configure("We.TNotebook.Tab", background=PANEL_BG, foreground=MUTED,
                         padding=(14, 8), font=("Segoe UI", 10, "bold"))
        style.map("We.TNotebook.Tab",
                  background=[("selected", ACCENT)],
                  foreground=[("selected", "white")])

    def _build_header(self):
        header = tk.Frame(self.root, bg=APP_BG)
        header.pack(fill="x", padx=20, pady=(20, 0))
        tk.Label(header, text="We Encrypt", bg=APP_BG, fg=FG,
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(header,
                 text="Password protect any .py file, and will be impossible to decrypt!*",
                 bg=APP_BG, fg=MUTED, font=("Segoe UI", 9), wraplength=520,
                 justify="left").pack(anchor="w", pady=(4, 0))
    def _labeled_entry(self, parent, label_text, show=None):
        tk.Label(parent, text=label_text, bg=PANEL_BG, fg=FG,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=20, pady=(16, 4))
        var = tk.StringVar()
        entry = tk.Entry(parent, textvariable=var, show=show, bg=FIELD_BG, fg=FG,
                          insertbackground=FG, relief="flat", font=("Segoe UI", 10))
        entry.pack(fill="x", padx=20, ipady=7)
        return var, entry

    def _file_picker_row(self, parent, label_text, button_text, command):
        tk.Label(parent, text=label_text, bg=PANEL_BG, fg=FG,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=20, pady=(16, 4))
        row = tk.Frame(parent, bg=PANEL_BG)
        row.pack(fill="x", padx=20)
        path_var = tk.StringVar(value="No file selected")
        path_label = tk.Label(row, textvariable=path_var, bg=FIELD_BG, fg=MUTED,
                               font=("Segoe UI", 9), anchor="w", padx=8)
        path_label.pack(side="left", fill="x", expand=True, ipady=7)
        browse_btn = tk.Button(row, text=button_text, command=command, bg="#3a3c4a",
                                fg=FG, relief="flat", font=("Segoe UI", 9), cursor="hand2",
                                activebackground="#4a4c5f", padx=10)
        browse_btn.pack(side="right", padx=(8, 0))
        return path_var, path_label

    def _action_button(self, parent, text, command):
        return tk.Button(parent, text=text, command=command, bg=ACCENT, fg="white",
                          relief="flat", font=("Segoe UI", 10, "bold"),
                          activebackground=ACCENT_HOVER, cursor="hand2", padx=18, pady=9)

    def _status_label(self, parent):
        var = tk.StringVar(value="")
        label = tk.Label(parent, textvariable=var, bg=PANEL_BG, fg=MUTED,
                          font=("Segoe UI", 9), wraplength=500, justify="left")
        label.pack(anchor="w", padx=20, pady=(10, 16))
        return var, label
    def _build_encrypt_tab(self):
        tab = self.encrypt_tab
        self.enc_src_var, _ = self._file_picker_row(
            tab, "Python file to encrypt", "Browse...", self._pick_encrypt_source)
        self.enc_pw_var, self.enc_pw_entry = self._labeled_entry(
            tab, "Choose a password", show="*")
        self.enc_pw2_var, self.enc_pw2_entry = self._labeled_entry(
            tab, "Confirm password", show="*")

        btn_row = tk.Frame(tab, bg=PANEL_BG)
        btn_row.pack(fill="x", padx=20, pady=(18, 0))
        self._action_button(btn_row, "Encrypt file", self._do_encrypt).pack(anchor="w")

        note = tk.Label(
            tab, text=" ",
            bg=PANEL_BG, fg=MUTED, font=("Segoe UI", 8), wraplength=500, justify="left")
        note.pack(anchor="w", padx=20, pady=(10, 0))

        self.enc_status_var, self.enc_status_label = self._status_label(tab)

    def _pick_encrypt_source(self):
        path = filedialog.askopenfilename(
            title="Choose a .py file", filetypes=[("Python files", "*.py")])
        if path:
            self.enc_src_var.set(path)

    def _do_encrypt(self):
        src = self.enc_src_var.get()
        if src == "No file selected" or not src:
            messagebox.showwarning("We Encrypt", "Choose a .py file first.")
            return
        pw = self.enc_pw_var.get()
        pw2 = self.enc_pw2_var.get()
        if not pw:
            messagebox.showwarning("We Encrypt", "Enter a password.")
            return
        if pw != pw2:
            messagebox.showwarning("We Encrypt", "Passwords do not match.")
            return

        if not messagebox.askyesno(
            "We Encrypt",
            f"This will encrypt:\n{src}\n\nin place with the locked "
            "version. You will not be able to view the Original Source Code without the Password. Continue?"
        ):
            return

        try:
            encrypt_file(src, pw)
        except WeEncryptError as e:
            messagebox.showerror("We Encrypt", str(e))
            return

        self.enc_pw_var.set("")
        self.enc_pw2_var.set("")
        self.enc_status_var.set(f"Encrypted in place: {src}")
        self.enc_status_label.config(fg=OK_COLOR)
        messagebox.showinfo(
            "We Encrypt",
            "Encrypted!\n\n")
    def _build_decrypt_tab(self):
        tab = self.decrypt_tab
        self.dec_src_var, _ = self._file_picker_row(
            tab, "Locked file to decrypt", "Browse...", self._pick_decrypt_source)
        self.dec_pw_var, self.dec_pw_entry = self._labeled_entry(
            tab, "Password", show="*")

        btn_row = tk.Frame(tab, bg=PANEL_BG)
        btn_row.pack(fill="x", padx=20, pady=(18, 0))
        self._action_button(btn_row, "Decrypt permanently", self._do_decrypt).pack(anchor="w")

        note = tk.Label(
            tab,
            text="This overwrites the locked file in place, permanently "
                 "removing the password gate and restoring clean plain "
                 "source. Requires the correct password.",
            bg=PANEL_BG, fg=MUTED, font=("Segoe UI", 8), wraplength=500, justify="left")
        note.pack(anchor="w", padx=20, pady=(10, 0))

        self.dec_status_var, self.dec_status_label = self._status_label(tab)

    def _pick_decrypt_source(self):
        path = filedialog.askopenfilename(
            title="Choose a locked .py file", filetypes=[("Python files", "*.py")])
        if path:
            self.dec_src_var.set(path)

    def _do_decrypt(self):
        src = self.dec_src_var.get()
        if src == "No file selected" or not src:
            messagebox.showwarning("We Encrypt", "Choose a locked .py file first.")
            return
        pw = self.dec_pw_var.get()
        if not pw:
            messagebox.showwarning("We Encrypt", "Enter the password.")
            return

        if not messagebox.askyesno(
            "We Encrypt",
            f"This will overwrite:\n{src}\n\nin place with the decrypted "
            "plain source, permanently removing the password gate. Continue?"
        ):
            return

        try:
            decrypt_file(src, pw)
        except WeEncryptError as e:
            self.dec_status_var.set(str(e))
            self.dec_status_label.config(fg=DANGER)
            messagebox.showerror("We Encrypt", str(e))
            return

        self.dec_pw_var.set("")
        self.dec_status_var.set(f"Decrypted in place: {src}")
        self.dec_status_label.config(fg=OK_COLOR)
        messagebox.showinfo("We Encrypt", "File decrypted in place.\n\nThe password gate has been permanently removed!")


def main():
    if "-dc" in sys.argv:
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo(
            "We Encrypt",
            "This is the We Encrypt app itself, not a locked file.\n\n"
            "Use the 'Decrypt a file' tab to permanently unlock a file, "
            "or run a locked file (one produced by 'Encrypt a file') with "
            "-dc to open its password window.")
        return

    root = tk.Tk()
    WeEncryptApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
