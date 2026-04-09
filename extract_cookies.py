#!/usr/bin/env python3
"""
Extract O'Reilly Learning cookies from your browser and write cookies.json.

Supports: Brave, Chrome (auto-detected, Brave preferred).

Usage:
    1. Log in to https://learning.oreilly.com/ in your browser
    2. Run: python3 extract_cookies.py
    3. Now run: python3 safaribooks.py <BOOK_ID>

Options:
    --login          Open login page in browser first, then extract
    --browser NAME   Force a specific browser (brave, chrome)
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import webbrowser

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


OREILLY_DOMAINS = [".oreilly.com", "learning.oreilly.com", "api.oreilly.com"]

# Akamai bot-detection cookies are session-bound and break when reused
SKIP_COOKIES = {"_abck", "ak_bmsc", "bm_sz", "bm_sv", "bm_s", "bm_so", "bm_ss", "bm_lso"}

BROWSER_COOKIE_DBS = {
    "brave": os.path.expanduser(
        "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies"
    ),
    "chrome": os.path.expanduser(
        "~/Library/Application Support/Google/Chrome/Default/Cookies"
    ),
}

BROWSER_KEYCHAIN_NAMES = {
    "brave": "Brave Safe Storage",
    "chrome": "Chrome Safe Storage",
}

COOKIES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cookies.json")


def get_browser_key(browser):
    """Get the browser's cookie encryption key from macOS Keychain."""
    service_name = BROWSER_KEYCHAIN_NAMES[browser]
    result = subprocess.run(
        ["security", "find-generic-password", "-w", "-s", service_name],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("Error: Could not retrieve %s encryption key from Keychain." % browser)
        sys.exit(1)
    return result.stdout.strip()


def derive_key(browser_password, browser="chrome"):
    """Derive the AES key from the browser's password using PBKDF2."""
    iterations = 1003 if browser == "chrome" else 1003
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=16,
        salt=b"saltysalt",
        iterations=iterations,
    )
    return kdf.derive(browser_password.encode("utf-8"))


def decrypt_cookie(encrypted_value, key):
    """Decrypt a Chrome/Brave cookie value."""
    if not encrypted_value:
        return ""

    # v10 prefix means encrypted with AES-CBC
    if encrypted_value[:3] == b"v10":
        encrypted_value = encrypted_value[3:]
        iv = b" " * 16
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_value) + decryptor.finalize()
        # Remove PKCS7 padding
        padding_len = decrypted[-1]
        if isinstance(padding_len, int) and 0 < padding_len <= 16:
            decrypted = decrypted[:-padding_len]
        # Brave prepends a 32-byte signature before the actual value.
        # Strip it by finding the \x02 separator.
        if b"\x02" in decrypted[:33]:
            decrypted = decrypted[decrypted.index(b"\x02") + 1:]
        elif b"~" in decrypted[:33]:
            # Akamai LB cookies: value starts at first ~
            decrypted = decrypted[decrypted.index(b"~"):]
        return decrypted.decode("ascii", errors="ignore")

    # Unencrypted
    return encrypted_value.decode("utf-8", errors="ignore")


def detect_browser():
    """Auto-detect which browser to use."""
    for browser, path in BROWSER_COOKIE_DBS.items():
        if os.path.isfile(path):
            return browser
    return None


def extract_cookies(browser=None):
    """Extract O'Reilly cookies from the browser."""
    if browser is None:
        browser = detect_browser()
        if browser is None:
            print("Error: No supported browser found (Brave, Chrome).")
            sys.exit(1)

    db_path = BROWSER_COOKIE_DBS[browser]
    if not os.path.isfile(db_path):
        print("Error: %s cookie database not found at:" % browser.title())
        print("  " + db_path)
        sys.exit(1)

    print("Using %s..." % browser.title())

    # Browser locks the DB, so copy it to a temp file
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    tmp.close()
    shutil.copy2(db_path, tmp.name)

    key = derive_key(get_browser_key(browser))

    cookies = {}
    try:
        conn = sqlite3.connect(tmp.name)
        cursor = conn.cursor()

        for domain in OREILLY_DOMAINS:
            cursor.execute(
                "SELECT name, encrypted_value, value FROM cookies WHERE host_key LIKE ?",
                ("%" + domain,)
            )
            for name, encrypted_value, value in cursor.fetchall():
                if name in SKIP_COOKIES:
                    continue
                if value:
                    cookies[name] = value
                elif encrypted_value:
                    decrypted = decrypt_cookie(encrypted_value, key)
                    if decrypted:
                        cookies[name] = decrypted

        conn.close()
    finally:
        os.unlink(tmp.name)

    return cookies


def main():
    # Parse --browser flag
    browser = None
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--browser" and i < len(sys.argv) - 1:
            browser = sys.argv[i + 1].lower()
            if browser not in BROWSER_COOKIE_DBS:
                print("Unsupported browser: %s. Supported: %s" % (browser, ", ".join(BROWSER_COOKIE_DBS)))
                sys.exit(1)

    # Check if user wants to open browser first
    if "--login" in sys.argv:
        print("Opening O'Reilly Learning in your browser...")
        print("Log in, then come back and press Enter.")
        webbrowser.open("https://learning.oreilly.com/")
        input("\nPress Enter after you've logged in...")

    print("Extracting cookies...")
    cookies = extract_cookies(browser)

    if not cookies:
        print("No O'Reilly cookies found in Chrome.")
        print("Make sure you're logged in at https://learning.oreilly.com/")
        print("Tip: run with --login to open the login page first.")
        sys.exit(1)

    # Check for the essential auth cookie
    has_auth = any(k in cookies for k in ["orm-jwt", "orm-rt", "BrowserCookie"])
    if not has_auth:
        print("Warning: No auth cookies found (orm-jwt, orm-rt).")
        print("You may not be logged in. Try: python3 extract_cookies.py --login")

    json.dump(cookies, open(COOKIES_FILE, "w"), indent=2)
    print("Wrote %d cookies to %s" % (len(cookies), COOKIES_FILE))
    print("\nCookies found: %s" % ", ".join(cookies.keys()))
    print("\nYou can now run: python3 safaribooks.py <BOOK_ID>")


if __name__ == "__main__":
    main()
