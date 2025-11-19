import tempfile
from pathlib import Path

from modules.classes import Host, ValidationError

def test_host_missing_username():
    cfg = {
        "address": "192.0.2.1",
        "os": "linux",
        "password": "pass",
    }
    try:
        Host("host1", cfg)
        print("[FAIL] test_host_missing_username: expected ValidationError")
        raise SystemExit(1)
    except ValidationError:
        print("[PASS] test_host_missing_username")


def test_host_missing_auth():
    cfg = {
        "username": "admin",
        "address": "192.0.2.2",
        "os": "linux",
    }
    try:
        Host("host2", cfg)
        print("[FAIL] test_host_missing_auth: expected ValidationError")
        raise SystemExit(1)
    except ValidationError:
        print("[PASS] test_host_missing_auth")


def test_network_device_requires_device_type():
    cfg = {
        "username": "netadmin",
        "password": "pw",
        "address": "192.0.2.3",
        "os": "network",
    }
    try:
        Host("net1", cfg)
        print("[FAIL] test_network_device_requires_device_type: expected ValidationError")
        raise SystemExit(1)
    except ValidationError:
        print("[PASS] test_network_device_requires_device_type")


def test_windows_certificate_auth(tmp_dir=None):
    # Create temp cert files
    with tempfile.TemporaryDirectory() as td:
        cert = Path(td) / "cert.pem"
        key = Path(td) / "key.pem"
        cert.write_text("CERT")
        key.write_text("KEY")

        cfg = {
            "username": "DOMAIN\\Administrator",
            "os": "windows",
            "address": "192.0.2.4",
            "auth_protocol": "certificate",
            "cert_pem": str(cert),
            "cert_key_pem": str(key),
        }
        try:
            h = Host("win1", cfg)
            cp = h.get_connection_params()
            assert cp.get("auth_protocol") == "certificate"
            assert cp.get("cert_pem") == str(cert)
            assert h.port == "5985"
            print("[PASS] test_windows_certificate_auth")
        except Exception as e:
            print(f"[FAIL] test_windows_certificate_auth: {e}")
            raise SystemExit(1)
