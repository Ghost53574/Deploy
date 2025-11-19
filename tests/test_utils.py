import tempfile
from pathlib import Path

from modules import utils
from modules.classes import Host

def test_parse_csv_and_create_hosts():
    csv_content = (
        "hostname,os,ip,tcp_ports,username,password,purpose,notes\n"
        "web1,linux,192.0.2.10,22,admin,pass,web,prod\n"
        "db1,linux,192.0.2.11,22,dbadmin,dbpass,db,staging\n"
    )

    with tempfile.TemporaryDirectory() as td:
        csv_path = Path(td) / "hosts.csv"
        csv_path.write_text(csv_content)

        records = utils.parse_csv_file(str(csv_path))
        assert isinstance(records, list)
        assert len(records) == 2

        hosts = utils.create_hosts_from_csv(records)
        # Expect two hosts created
        assert "web1" in hosts
        assert "db1" in hosts
        h = hosts["web1"]
        assert isinstance(h, Host)
        assert h.address == "192.0.2.10"
        assert h.username == "admin"


def test_create_hosts_from_json():
    config = {
        "web2": {
            "username": "admin",
            "password": "pw",
            "os": "linux",
            "address": "192.0.2.20",
            "port": "22",
        }
    }
    hosts = utils.create_hosts_from_json(config)
    assert "web2" in hosts
    h = hosts["web2"]
    assert isinstance(h, Host)
    assert h.address == "192.0.2.20"
    assert h.username == "admin"