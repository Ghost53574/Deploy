from modules.classes import Host, Settings
from modules.connections import ConnectionFactory, SSHConnection, WinRMConnection, NetmikoConnection

def make_host(name, cfg):
    return Host(name, cfg)

def test_connection_factory_types():
    # Linux host -> SSHConnection
    linux_cfg = {"username": "u", "password": "p", "os": "linux", "address": "192.0.2.10"}
    linux = make_host("linux1", linux_cfg)
    settings = Settings()
    conn = ConnectionFactory.create_connection(linux, settings)
    assert isinstance(conn, SSHConnection)

    # Windows host -> WinRMConnection
    win_cfg = {"username": "Administrator", "password": "pw", "os": "windows", "address": "192.0.2.11"}
    win = make_host("win1", win_cfg)
    conn2 = ConnectionFactory.create_connection(win, settings)
    assert isinstance(conn2, WinRMConnection)

    # Network device -> NetmikoConnection (requires device_type)
    net_cfg = {"username": "netadmin", "password": "npw", "os": "network", "address": "192.0.2.12", "device_type": "cisco_ios"}
    net = make_host("net1", net_cfg)
    conn3 = ConnectionFactory.create_connection(net, settings)
    assert isinstance(conn3, NetmikoConnection)

    print("[PASS] test_connection_factory_types")

if __name__ == "__main__":
    test_connection_factory_types()
