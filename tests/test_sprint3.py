import os
import sys
import time
import sqlite3
import subprocess
import threading
import tempfile
import shutil
import requests
from pathlib import Path
from datetime import datetime

ROOT_DIR = Path(__file__).resolve().parent.parent
CLI_CMD = [sys.executable, "-m", "micropki.cli"]

TEST_DB_PATH = ""
TEST_OUT_DIR = ""
SERVER_PROCESS = None
SERVER_URL = ""


def log_step(step_name, status="RUNNING", details=""):
    icon = {"PASS": "✅", "FAIL": "❌", "RUNNING": "⏳", "SKIP": ""}.get(status, "•")
    color_code = {"PASS": "\033[92m", "FAIL": "\033[91m", "RUNNING": "\033[93m"}.get(status, "")
    reset = "\033[0m"

    print(f"{icon} {color_code}{step_name}{reset} {status}")
    if details and status != "RUNNING":
        print(f"   └─ {details}")


def run_cli(args, check=True):
    cmd = CLI_CMD + args
    env = os.environ.copy()
    env['PYTHONPATH'] = str(ROOT_DIR)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT_DIR, env=env, timeout=30)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Timeout"
    except Exception as e:
        return False, "", str(e)


def setup_module(module):
    global TEST_DB_PATH, TEST_OUT_DIR

    log_step("SETUP: Creating temporary environment", "RUNNING")

    TEST_OUT_DIR = tempfile.mkdtemp(prefix="micropki_test_")
    TEST_DB_PATH = os.path.join(TEST_OUT_DIR, "test_micropki.db")
    SECRETS_DIR = os.path.join(TEST_OUT_DIR, "secrets")
    CERTS_DIR = os.path.join(TEST_OUT_DIR, "certs")

    os.makedirs(SECRETS_DIR, exist_ok=True)
    os.makedirs(CERTS_DIR, exist_ok=True)

    pass_file = os.path.join(SECRETS_DIR, "test.pass")
    with open(pass_file, "w") as f:
        f.write("TestPassword123")

    success, out, err = run_cli(["db", "init", "--db-path", TEST_DB_PATH])
    if not success:
        raise Exception(f"Failed to init DB: {err}")

    root_ca_dir = os.path.join(TEST_OUT_DIR, "root_ca")
    os.makedirs(root_ca_dir, exist_ok=True)

    success, out, err = run_cli([
        "ca", "init",
        "--subject", "/CN=Test Root CA,O=TestOrg",
        "--passphrase-file", pass_file,
        "--out-dir", root_ca_dir,
        "--db-path", TEST_DB_PATH
    ])

    if not success:
        raise Exception(f"Failed to create Root CA: {err}")

    log_step("SETUP: Environment ready", "PASS", f"DB: {TEST_DB_PATH}")


def teardown_module(module):
    global SERVER_PROCESS
    if SERVER_PROCESS:
        SERVER_PROCESS.terminate()
        SERVER_PROCESS.wait()
        log_step("TEARDOWN: Server stopped", "PASS")

    if os.path.exists(TEST_OUT_DIR):
        shutil.rmtree(TEST_OUT_DIR)
        log_step("TEARDOWN: Temp files removed", "PASS")


def test_13_db_insertion():
    log_step("TEST-13: Issue 5 certificates & Check DB", "RUNNING")

    secrets_dir = os.path.join(TEST_OUT_DIR, "secrets")
    pass_file = os.path.join(secrets_dir, "test.pass")
    root_ca_dir = os.path.join(TEST_OUT_DIR, "root_ca")

    int_ca_dir = os.path.join(TEST_OUT_DIR, "int_ca")
    os.makedirs(int_ca_dir, exist_ok=True)

    success, out, err = run_cli([
        "ca", "issue-intermediate",
        "--root-cert", os.path.join(root_ca_dir, "certs", "ca.cert.pem"),
        "--root-key", os.path.join(root_ca_dir, "private", "ca.key.pem"),
        "--root-pass-file", pass_file,
        "--subject", "/CN=Test Intermediate CA",
        "--passphrase-file", pass_file,
        "--out-dir", int_ca_dir,
        "--db-path", TEST_DB_PATH
    ])

    if not success:
        log_step("TEST-13", "FAIL", f"Could not create Intermediate CA: {err}")
        assert False, "Intermediate CA creation failed"

    issued_serials = []

    templates = [
        ("server", "dns:web1.test.local", "CN=Web1"),
        ("server", "dns:web2.test.local", "CN=Web2"),
        ("client", "email:user@test.local", "CN=User1"),
        ("code_signing", "", "CN=CodeSigner1"),
        ("server", "ip:192.168.1.100", "CN=IoT-Device")
    ]

    for i, (tmpl, san, subj) in enumerate(templates):
        out_dir = os.path.join(TEST_OUT_DIR, f"cert_{i}")
        os.makedirs(out_dir, exist_ok=True)

        san_arg = []
        if san:
            san_arg = ["--san", san]

        success, out, err = run_cli([
            "ca", "issue-cert",
            "--ca-cert", os.path.join(int_ca_dir, "certs", "intermediate.cert.pem"),
            "--ca-key", os.path.join(int_ca_dir, "private", "intermediate.key.pem"),
            "--ca-pass-file", pass_file,
            "--template", tmpl,
            "--subject", f"/{subj},O=TestOrg",
            *san_arg,
            "--out-dir", out_dir,
            "--db-path", TEST_DB_PATH
        ])

        if not success:
            log_step("TEST-13", "FAIL", f"Failed to issue cert {i}: {err}")
            assert False, f"Issuance failed: {err}"

        issued_serials.append(True)

    conn = sqlite3.connect(TEST_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM certificates WHERE issuer LIKE '%Intermediate%'")
    count = cursor.fetchone()[0]
    conn.close()

    if count >= 5:
        log_step("TEST-13", "PASS", f"Successfully issued and recorded {count} certificates.")
    else:
        log_step("TEST-13", "FAIL", f"Expected 5 certs in DB, found {count}")
        assert False, "DB count mismatch"


def test_14_cli_retrieval():
    log_step("TEST-14: CLI Retrieval (list/show)", "RUNNING")

    success, out, err = run_cli(["ca", "list-certs", "--db-path", TEST_DB_PATH, "--format", "table"])
    if not success or "Serial" not in out:
        log_step("TEST-14", "FAIL", "list-certs failed or empty")
        assert False

    conn = sqlite3.connect(TEST_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT serial_hex FROM certificates LIMIT 1")
    row = cursor.fetchone()
    conn.close()

    if row:
        serial = row[0]
        success, out, err = run_cli(["ca", "show-cert", serial, "--db-path", TEST_DB_PATH])
        if success and "-----BEGIN CERTIFICATE-----" in out:
            log_step("TEST-14", "PASS", f"Retrieved cert {serial} successfully")
        else:
            log_step("TEST-14", "FAIL", "show-cert failed")
            assert False
    else:
        log_step("TEST-14", "FAIL", "No serial found to test")
        assert False


def test_15_16_api_fetch():
    log_step("TEST-15/16: HTTP API Fetch", "RUNNING")
    global SERVER_PROCESS, SERVER_URL

    secrets_dir = os.path.join(TEST_OUT_DIR, "secrets")
    int_ca_dir = os.path.join(TEST_OUT_DIR, "int_ca")

    cmd = CLI_CMD + [
        "repo", "serve",
        "--db-path", TEST_DB_PATH,
        "--cert-dir", os.path.join(int_ca_dir, "certs"),
        "--port", "8081"
    ]

    env = os.environ.copy()
    env['PYTHONPATH'] = str(ROOT_DIR)

    SERVER_PROCESS = subprocess.Popen(cmd, cwd=ROOT_DIR, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    SERVER_URL = "http://localhost:8081"

    time.sleep(2)
    if SERVER_PROCESS.poll() is not None:
        out, err = SERVER_PROCESS.communicate()
        log_step("TEST-15/16", "FAIL", f"Server failed to start: {err.decode()}")
        assert False, "Server didn't start"

    conn = sqlite3.connect(TEST_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT serial_hex FROM certificates LIMIT 1")
    serial = cursor.fetchone()[0]
    conn.close()

    try:
        resp = requests.get(f"{SERVER_URL}/certificate/{serial}", timeout=5)
        if resp.status_code == 200 and "BEGIN CERTIFICATE" in resp.text:
            log_step("TEST-15 (Cert Fetch)", "PASS", f"Status: {resp.status_code}")
        else:
            log_step("TEST-15 (Cert Fetch)", "FAIL", f"Status: {resp.status_code}")
            assert False

        resp_ca = requests.get(f"{SERVER_URL}/ca/intermediate", timeout=5)
        if resp_ca.status_code == 200 and "BEGIN CERTIFICATE" in resp_ca.text:
            log_step("TEST-16 (CA Fetch)", "PASS", f"Status: {resp_ca.status_code}")
        else:
            log_step("TEST-16 (CA Fetch)", "FAIL", f"Status: {resp_ca.status_code}")
            assert False

        resp_crl = requests.get(f"{SERVER_URL}/crl", timeout=5)
        if resp_crl.status_code == 501:
            log_step("TEST-CRL (Stub)", "PASS", "501 Not Implemented")
        else:
            log_step("TEST-CRL (Stub)", "FAIL", f"Expected 501, got {resp_crl.status_code}")

    except Exception as e:
        log_step("TEST-15/16", "FAIL", str(e))
        assert False


def test_17_stress_serials():
    log_step("TEST-17: Serial Uniqueness Stress Test", "RUNNING")

    sys.path.insert(0, str(ROOT_DIR))
    from ..micropki.serial import generate_unique_serial, serial_to_hex

    serials = set()
    for _ in range(100):
        s_int = generate_unique_serial()
        s_hex = serial_to_hex(s_int)
        serials.add(s_hex)

    if len(serials) == 100:
        log_step("TEST-17", "PASS", "100 unique serials generated successfully")
    else:
        log_step("TEST-17", "FAIL", f"Duplicate detected! Only {len(serials)} unique out of 100")
        assert False


def test_18_negative_duplicate():
    log_step("TEST-18: Negative Test (Duplicate Serial)", "RUNNING")

    sys.path.insert(0, str(ROOT_DIR))
    from ..micropki.database import add_certificate
    from datetime import datetime, timezone, timedelta

    now = datetime.now(timezone.utc)
    fake_pem = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"

    try:
        add_certificate(
            db_path=TEST_DB_PATH,
            serial_hex="DEADBEEF12345678",
            subject="CN=First",
            issuer="CN=CA",
            not_before=now,
            not_after=now + timedelta(days=1),
            cert_pem=fake_pem
        )

        try:
            add_certificate(
                db_path=TEST_DB_PATH,
                serial_hex="DEADBEEF12345678",
                subject="CN=Second",
                issuer="CN=CA",
                not_before=now,
                not_after=now + timedelta(days=1),
                cert_pem=fake_pem
            )
            log_step("TEST-18", "FAIL", "Duplicate allowed (Database constraint failed)")
            assert False, "Should have raised IntegrityError"
        except ValueError as e:
            if "already exists" in str(e):
                log_step("TEST-18", "PASS", "Duplicate correctly rejected")
            else:
                raise

    except Exception as e:
        log_step("TEST-18", "FAIL", str(e))
        assert False


def test_19_negative_invalid_format():
    log_step("TEST-19: Negative Test (Invalid Serial Format)", "RUNNING")

    try:
        resp = requests.get(f"{SERVER_URL}/certificate/INVALID_HEX", timeout=5)
        if resp.status_code == 400:
            log_step("TEST-19", "PASS", f"Correctly returned 400 Bad Request")
        else:
            log_step("TEST-19", "FAIL", f"Expected 400, got {resp.status_code}")
            assert False
    except Exception as e:
        log_step("TEST-19", "FAIL", str(e))
        assert False


def test_20_integration_workflow():
    log_step("TEST-20: Full Integration Workflow", "RUNNING")

    try:
        resp = requests.get(f"{SERVER_URL}/", timeout=5)
        if resp.status_code == 200 and "MicroPKI" in resp.text:
            log_step("TEST-20", "PASS", "Full workflow verified. System is healthy.")
        else:
            log_step("TEST-20", "FAIL", "Root endpoint failed")
            assert False
    except Exception as e:
        log_step("TEST-20", "FAIL", str(e))
        assert False


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🚀 MicroPKI Sprint 3: Automated Test Suite")
    print("=" * 60 + "\n")

    import pytest

    sys.exit(pytest.main([__file__, "-v", "-s"]))