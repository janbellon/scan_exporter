# scan_exporter
A basic Prometheus exporter that counts the number of connections per port and source ip for the last hour.

## Installation
Download the latest script
```bash
export VERSION=v0.1.0
wget https://github.com/janbellon/releases/download/${VERSION}/scan_exporter.py -o /usr/local/bin/scan_exporter.py
```

Create a scan-exporter user
```bash
useradd -M -s /bin/false scan-exporter
```

Create a python environment and install prometheus-client
```bash
python3 -m venv /var/env
source /var/env/bin/python3
pip install prometheus-client
```

Create a systemd service in `/etc/systemd/system/scan_exporter`
```ini
[Unit]
Description=Prometheus Scan Exporter
Documentation=https://github.com/janbellon/scan_exporter
After=network-online.target
Wants=network-online.target

[Service]
Type=simple

User=scan-exporter
Group=scan-exporter

ExecStart=/var/env/bin/python3 /usr/local/bin/scan_exporter.py

Restart=always
RestartSec=5

Environment=UFW_EXPORTER_PORT=9192
Environment=UFW_EXPORTER_IP_TTL_SECONDS=3600
Environment=UFW_EXPORTER_CLEANUP_INTERVAL_SECONDS=60

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```
