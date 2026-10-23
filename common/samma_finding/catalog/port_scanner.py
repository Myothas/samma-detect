"""Checks for port-scanner. Closed ports are not findings; an open port is
one finding per port with the per-address detail under ``raw``."""

PREFIX = "SAMMA-PORT-"

# Ports that carry management, database or cluster-internal services. Any of
# these reachable from the internet is HIGH; every other open port is INFO.
ADMIN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 111: "rpcbind", 135: "msrpc",
    139: "netbios", 445: "smb", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2375: "docker", 2376: "docker-tls", 2379: "etcd", 2380: "etcd-peer",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc", 5901: "vnc",
    5984: "couchdb", 5985: "winrm", 5986: "winrm-https", 6379: "redis",
    9042: "cassandra", 9092: "kafka", 9200: "elasticsearch",
    9300: "elasticsearch-transport", 10250: "kubelet", 11211: "memcached",
    15672: "rabbitmq-management", 27017: "mongodb", 27018: "mongodb",
    27019: "mongodb",
}

SCHEMES = {80: "http", 443: "https", 8080: "http", 8443: "https", 22: "ssh"}

CHECKS = {
    "SAMMA-PORT-OPEN-ADMIN": {
        "severity": "HIGH",
        "title": "Administrative or database port is reachable from the internet",
        "remediation": "Close the port at the firewall or load balancer, or restrict it "
                       "to trusted networks (VPN, bastion host, private peering). "
                       "Management and database services should not be reachable "
                       "from the public internet.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
            "https://www.cisecurity.org/controls/v8",
        ],
    },
    "SAMMA-PORT-OPEN": {
        "severity": "INFO",
        "title": "TCP port is open",
        "remediation": "No action is needed when the service is meant to be public. "
                       "Otherwise close the port or restrict it at the firewall.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
        ],
    },
}
