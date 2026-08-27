#!/usr/bin/env python3
"""A localhost-only web UI for fencrypt.

This is a thin wrapper around encrypt_bytes/decrypt_bytes in fencrypt.py -- all
the actual cryptography lives there and is unchanged.

Security notes, because a browser UI changes the threat model:
  * Bound to 127.0.0.1 only. This must never listen on a public interface: the
    password crosses from the page to this process in a form body.
  * Plaintext and passwords stay in memory. Nothing is written to a temp file
    or logged.
  * Uploads are size-capped, since each request holds the whole file in RAM.
"""
from __future__ import annotations

import io

from flask import Flask, jsonify, render_template, request, send_file

from fencrypt import decrypt_bytes, encrypt_bytes

MAX_UPLOAD = 25 * 1024 * 1024  # 25 MiB

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD


@app.get("/")
def index():
    return render_template("index.html", max_mb=MAX_UPLOAD // (1024 * 1024))


@app.post("/process")
def process():
    mode = request.form.get("mode", "")
    password = request.form.get("password", "")
    upload = request.files.get("file")

    if mode not in ("encrypt", "decrypt"):
        return jsonify(error="pick encrypt or decrypt"), 400
    if not upload or not upload.filename:
        return jsonify(error="choose a file first"), 400
    if not password:
        return jsonify(error="a password is required"), 400

    data = upload.read()
    pw = password.encode("utf-8")

    try:
        if mode == "encrypt":
            out = encrypt_bytes(data, pw)
            name = upload.filename + ".enc"
        else:
            out = decrypt_bytes(data, pw)
            name = upload.filename[:-4] if upload.filename.endswith(".enc") else upload.filename + ".dec"
    except ValueError as exc:
        # Covers a wrong password, a tampered file, and a hostile header. The
        # message is already user-facing and leaks nothing about the key.
        return jsonify(error=str(exc)), 400
    except MemoryError:
        return jsonify(error="not enough memory to derive the key"), 400

    resp = send_file(
        io.BytesIO(out),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=name,
    )
    # Simpler for the page to read than parsing Content-Disposition.
    resp.headers["X-Filename"] = name
    resp.headers["Access-Control-Expose-Headers"] = "X-Filename"
    return resp


if __name__ == "__main__":
    # host is hardcoded to loopback on purpose -- see the module docstring.
    app.run(host="127.0.0.1", port=5057, debug=False)
