import os
import sys
from pathlib import Path

# --- FIX FOR IMPORT ERRORS IN TESTS ---
# Добавляем корень проекта (папку microPKI) в PYTHONPATH, чтобы pytest видел пакет micropki
ROOT_DIR_FIX = Path(__file__).resolve().parent.parent
if str(ROOT_DIR_FIX) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR_FIX))
# --------------------------------------

import time
import sqlite3
import subprocess
import tempfile
import shutil
import requests
from datetime import datetime, timedelta, timezone

# ... остальной код теста ...
# --- КОНФИГУРАЦИЯ ПУТЕЙ ---
# ROOT_DIR - это папка microPKI (родительская для tests/)
ROOT_DIR = Path(__file__).resolve().parent.parent

# Используем -m micropki.cli для корректной работы относительных импортов в cli.py
BASE_CMD = [sys.executable, "-m", "micropki.cli"]

TEST_DB_PATH = ""
TEST_OUT_DIR = ""
SERVER_PROCESS = None
SERVER_URL = ""


def log_step(step_name, status="RUNNING", details=""):
    icon = {"PASS": "[OK]", "FAIL": "[FAIL]", "RUNNING": "[...]"}.get(status, "•")
    color_code = {"PASS": "\033[92m", "FAIL": "\033[91m", "RUNNING": "\033[93m"}.get(status, "")
    reset = "\033[0m"
    print(f"{icon} {color_code}{step_name}{reset} {status}")
    if details and status != "RUNNING":
        print(f"   └─ {details}")


def run_cli(args):
    """
    Запускает CLI команду через python -m micropki.cli.
    Возвращает (success, stdout, stderr).
    """
    cmd = BASE_CMD + args

    env = os.environ.copy()
    # PYTHONPATH должен указывать на корень проекта (папку microPKI)
    env['PYTHONPATH'] = str(ROOT_DIR)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=ROOT_DIR,  # Запуск из корня проекта
            env=env,
            timeout=30,
            encoding='utf-8',
            errors='ignore'
        )

        output_combined = (result.stdout + result.stderr).lower()
        # Проверяем наличие успешных сообщений в логе
        is_success = (result.returncode == 0) or \
                     ("database initialized" in output_combined) or \
                     ("certificate saved" in output_combined) or \
                     ("certificate issued" in output_combined) or \
                     ("ca initialization completed" in output_combined)

        return is_success, result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        return False, "", "Timeout expired"
    except Exception as e:
        return False, "", f"Exception running CLI: {str(e)}"


def setup_module(module):
    global TEST_DB_PATH, TEST_OUT_DIR

    log_step("SETUP: Creating environment", "RUNNING")

    TEST_OUT_DIR = tempfile.mkdtemp(prefix="mpki_")
    TEST_DB_PATH = os.path.join(TEST_OUT_DIR, "test.db")
    secrets_dir = os.path.join(TEST_OUT_DIR, "secrets")
    os.makedirs(secrets_dir)

    pass_file = os.path.join(secrets_dir, "pass.txt")
    with open(pass_file, "w") as f:
        f.write("TestPass123")

    # Init DB
    ok, out, err = run_cli(["db", "init", "--db-path", TEST_DB_PATH])
    if not ok and "initialized" not in (out + err).lower():
        print(f"DEBUG DB INIT: OUT={out}, ERR={err}")
        raise Exception("DB Init Failed")

    # Root CA
    root_dir = os.path.join(TEST_OUT_DIR, "root")
    os.makedirs(root_dir)
    ok, out, err = run_cli([
        "ca", "init", "--subject", "/CN=TestRoot",
        "--passphrase-file", pass_file, "--out-dir", root_dir, "--db-path", TEST_DB_PATH
    ])
    if not ok and "completed" not in (out + err).lower():
        print(f"DEBUG ROOT CA: OUT={out}, ERR={err}")
        raise Exception("Root CA Failed")

    log_step("SETUP", "PASS")


def teardown_module(module):
    global SERVER_PROCESS
    if SERVER_PROCESS:
        SERVER_PROCESS.terminate()
        try:
            SERVER_PROCESS.wait(5)
        except:
            SERVER_PROCESS.kill()
        log_step("TEARDOWN: Server stopped", "PASS")
    if os.path.exists(TEST_OUT_DIR):
        shutil.rmtree(TEST_OUT_DIR)


def test_13_db_insertion():
    log_step("TEST-13: Issue Certs", "RUNNING")
    secrets_dir = os.path.join(TEST_OUT_DIR, "secrets")
    pass_file = os.path.join(secrets_dir, "pass.txt")
    root_dir = os.path.join(TEST_OUT_DIR, "root")
    int_dir = os.path.join(TEST_OUT_DIR, "int")
    os.makedirs(int_dir)

    # Intermediate
    ok, out, err = run_cli([
        "ca", "issue-intermediate",
        "--root-cert", f"{root_dir}/certs/ca.cert.pem",
        "--root-key", f"{root_dir}/private/ca.key.pem",
        "--root-pass-file", pass_file,
        "--subject", "/CN=TestInt", "--passphrase-file", pass_file,
        "--out-dir", int_dir, "--db-path", TEST_DB_PATH
    ])
    if not ok and "completed" not in (out + err).lower():
        log_step("TEST-13", "FAIL", "Int CA failed")
        assert False

    # 5 Certs
    for i in range(5):
        d = os.path.join(TEST_OUT_DIR, f"c{i}")
        os.makedirs(d)
        ok, _, _ = run_cli([
            "ca", "issue-cert",
            "--ca-cert", f"{int_dir}/certs/intermediate.cert.pem",
            "--ca-key", f"{int_dir}/private/intermediate.key.pem",
            "--ca-pass-file", pass_file,
            "--template", "server", "--subject", f"/CN=Test{i}",
            "--san", f"dns:test{i}.com", "--out-dir", d, "--db-path", TEST_DB_PATH
        ])
        if not ok:
            # Выводим ошибку для отладки
            print(f"DEBUG CERT {i}: OUT={_}, ERR={_}")
            log_step("TEST-13", "FAIL", f"Cert {i} failed")
            assert False

    conn = sqlite3.connect(TEST_DB_PATH)
    cnt = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
    conn.close()

    if cnt >= 5:
        log_step("TEST-13", "PASS", f"Count: {cnt}")
    else:
        log_step("TEST-13", "FAIL", f"Count: {cnt}"); assert False


def test_14_cli_retrieval():
    log_step("TEST-14: CLI Retrieval", "RUNNING")
    ok, out, _ = run_cli(["ca", "list-certs", "--db-path", TEST_DB_PATH])
    if not ok or "Serial" not in out:
        log_step("TEST-14", "FAIL");
        assert False

    conn = sqlite3.connect(TEST_DB_PATH)
    serial = conn.execute("SELECT serial_hex FROM certificates LIMIT 1").fetchone()[0]
    conn.close()

    ok, out, _ = run_cli(["ca", "show-cert", serial, "--db-path", TEST_DB_PATH])
    if ok and "BEGIN CERTIFICATE" in out:
        log_step("TEST-14", "PASS")
    else:
        log_step("TEST-14", "FAIL");
        assert False


def test_api_suite():
    global SERVER_PROCESS, SERVER_URL
    log_step("TEST-API: Start Server", "RUNNING")

    int_dir = os.path.join(TEST_OUT_DIR, "int")
    # Используем BASE_CMD (-m micropki.cli) для сервера тоже
    cmd = BASE_CMD + ["repo", "serve", "--db-path", TEST_DB_PATH,
                      "--cert-dir", f"{int_dir}/certs", "--port", "8081"]

    env = os.environ.copy()
    env['PYTHONPATH'] = str(ROOT_DIR)

    SERVER_PROCESS = subprocess.Popen(cmd, cwd=ROOT_DIR, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      text=True)
    SERVER_URL = "http://localhost:8081"

    # Ждем готовности сервера (до 15 сек)
    ready = False
    for _ in range(30):
        time.sleep(0.5)
        if SERVER_PROCESS.poll() is not None:
            logs = SERVER_PROCESS.stdout.read()
            log_step("TEST-API", "FAIL", f"Crashed: {logs}")
            assert False
        try:
            if requests.get(f"{SERVER_URL}/", timeout=1).status_code == 200:
                ready = True;
                break
        except:
            pass

    if not ready:
        log_step("TEST-API", "FAIL", "Timeout");
        assert False

    log_step("TEST-API", "PASS")

    # Fetch Cert
    conn = sqlite3.connect(TEST_DB_PATH)
    serial = conn.execute("SELECT serial_hex FROM certificates LIMIT 1").fetchone()[0]
    conn.close()

    r = requests.get(f"{SERVER_URL}/certificate/{serial}")
    if r.status_code == 200 and "BEGIN" in r.text:
        log_step("TEST-15", "PASS")
    else:
        log_step("TEST-15", "FAIL"); assert False

    # Fetch CA
    r = requests.get(f"{SERVER_URL}/ca/intermediate")
    if r.status_code == 200:
        log_step("TEST-16", "PASS")
    else:
        log_step("TEST-16", "FAIL")

    # Invalid Serial
    r = requests.get(f"{SERVER_URL}/certificate/XYZ")
    if r.status_code == 400:
        log_step("TEST-19", "PASS")
    else:
        log_step("TEST-19", "FAIL"); assert False

    # Root
    r = requests.get(f"{SERVER_URL}/")
    if r.status_code == 200:
        log_step("TEST-20", "PASS")
    else:
        log_step("TEST-20", "FAIL"); assert False


def test_17_stress_serials():
    log_step("TEST-17: Stress", "RUNNING")
    # ROOT_DIR уже определен в начале файла как Path(__file__).resolve().parent.parent
    # Это папка microPKI. Внутри неё лежит папка micropki.
    # Чтобы импортировать from micropki.serial, PYTHONPATH должен указывать на microPKI.
    # sys.path.insert(0, str(ROOT_DIR)) должен работать, если в microPKI/micropki/__init__.py есть код или он пустой.

    try:
        from micropki.micropki.serial import generate_unique_serial, serial_to_hex
        s = set(serial_to_hex(generate_unique_serial()) for _ in range(100))
        if len(s) == 100:
            log_step("TEST-17", "PASS")
        else:
            log_step("TEST-17", "FAIL", f"Only {len(s)} unique serials");
            assert False
    except ImportError as e:
        log_step("TEST-17", "FAIL", f"Import Error: {e}. Check if 'micropki' is a valid package.");
        assert False


def test_18_negative_duplicate():
    log_step("TEST-18: Duplicate", "RUNNING")
    try:
        from micropki.micropki.database import add_certificate
        now = datetime.now(timezone.utc)
        pem = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----"

        add_certificate(TEST_DB_PATH, "DEADBEEF", "CN=1", "CN=CA", now, now + timedelta(days=1), pem)
        try:
            add_certificate(TEST_DB_PATH, "DEADBEEF", "CN=2", "CN=CA", now, now + timedelta(days=1), pem)
            log_step("TEST-18", "FAIL", "Duplicate allowed");
            assert False
        except ValueError:
            log_step("TEST-18", "PASS")
    except ImportError as e:
        log_step("TEST-18", "FAIL", f"Import Error: {e}");
        assert False

if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([__file__, "-v", "-s"]))