# ports.py — TCP port → service name mapping for NetProbe

COMMON_PORTS = {
    # ── File Transfer ──────────────────────────────
    20:    "FTP-Data",
    21:    "FTP",
    69:    "TFTP",
    115:   "SFTP",
    989:   "FTPS-Data",
    990:   "FTPS",

    # ── Remote Access ──────────────────────────────
    22:    "SSH",
    23:    "Telnet",
    3389:  "RDP",
    5900:  "VNC",
    5901:  "VNC-1",
    5902:  "VNC-2",

    # ── Mail ───────────────────────────────────────
    25:    "SMTP",
    110:   "POP3",
    143:   "IMAP",
    465:   "SMTPS",
    587:   "SMTP-Submit",
    993:   "IMAPS",
    995:   "POP3S",

    # ── Web ────────────────────────────────────────
    80:    "HTTP",
    443:   "HTTPS",
    8008:  "HTTP-Alt2",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "HTTP-Dev",
    9000:  "HTTP-Misc",
    9090:  "HTTP-Misc2",

    # ── DNS & Directory ────────────────────────────
    53:    "DNS",
    88:    "Kerberos",
    389:   "LDAP",
    636:   "LDAPS",

    # ── Windows / SMB / AD ─────────────────────────
    135:   "RPC",
    137:   "NetBIOS-NS",
    138:   "NetBIOS-DGM",
    139:   "NetBIOS",
    445:   "SMB",
    593:   "RPC-HTTP",

    # ── Databases ──────────────────────────────────
    1433:  "MSSQL",
    1521:  "Oracle",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    5984:  "CouchDB",
    6379:  "Redis",
    7474:  "Neo4j",
    9042:  "Cassandra",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch-Cluster",
    27017: "MongoDB",
    27018: "MongoDB-Shard",
    28017: "MongoDB-Web",

    # ── Message Queues & Streaming ─────────────────
    1883:  "MQTT",
    4369:  "EPMD-RabbitMQ",
    5671:  "AMQPS",
    5672:  "AMQP",
    9092:  "Kafka",
    15672: "RabbitMQ-Mgmt",
    61613: "STOMP",
    61616: "ActiveMQ",

    # ── Infrastructure & DevOps ────────────────────
    2375:  "Docker",
    2376:  "Docker-TLS",
    2379:  "etcd",
    2380:  "etcd-Cluster",
    6443:  "Kubernetes-API",
    8500:  "Consul",
    8600:  "Consul-DNS",
    9443:  "Portainer",

    # ── Monitoring ─────────────────────────────────
    161:   "SNMP",
    162:   "SNMP-Trap",
    3000:  "Grafana",
    9090:  "Prometheus",
    9100:  "Node-Exporter",
    9104:  "MySQL-Exporter",
    4317:  "OTLP-gRPC",
    4318:  "OTLP-HTTP",

    # ── Misc / Network Services ────────────────────
    7:     "Echo",
    13:    "Daytime",
    19:    "Chargen",
    37:    "Time",
    79:    "Finger",
    111:   "RPCBind",
    119:   "NNTP",
    123:   "NTP",
    179:   "BGP",
    194:   "IRC",
    500:   "IKE",
    514:   "Syslog",
    515:   "LPD",
    520:   "RIP",
    631:   "IPP-Cups",
    1080:  "SOCKS",
    1194:  "OpenVPN",
    1723:  "PPTP",
    4444:  "Metasploit",
    5000:  "Flask-Dev",
    5601:  "Kibana",
    6000:  "X11",
    6667:  "IRC",
    8009:  "AJP",
    9418:  "Git",
    10000: "Webmin",
    11211: "Memcached",
    27015: "Steam",
}
