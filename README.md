# Integrated network discovery and honeypot system

Thesis lab prototype using Nmap, HoneyChart, Helm, and K3s.

## Current commands

Deploy from a fresh lab scan:
    ./deploy.sh

Generate a report for a UTC time window:
    ./report.sh 2026-09-20T00:00:00Z 2026-09-22T00:00:00Z

deploy.sh runs run_pipeline_v7.sh.
report.sh runs collect_report.sh.

## Lab

Controller and honeypot host: 192.168.77.10
SSH and HTTP target: 192.168.77.20
SSH-only target: 192.168.77.21
Discovery subnet: 192.168.77.0/24
Lab interface: enp0s8
Scanned TCP ports: 22, 80, 443, 445
Helm release: auto-mixed-01
Kubernetes namespace: honeypots

HoneyChart must run at http://127.0.0.1:8081 for deployment.
Reporting does not require HoneyChart.
NodePorts can change; read the current Kubernetes Service.

## Storage

Persistent state: /var/lib/thesis-honeypots/auto-mixed-01/
Logs: /var/log/honeypots/auto-mixed-01/
Scan and deployment evidence: ~/thesis/runs/
Reports: ~/thesis/reports/
Pinned container images: image-pins.yaml

## Scope and limitations

Setup currently requires the prepared lab and initialized data directories.
This is not yet a clean-install bootstrap tool.

Profiles describe services observed within the scan scope.
Shared honeypots emulate services, not complete device identities.
Reports count connection starts, not confirmed attacks.
Controlled tests are labelled using explicit event IDs.
Reporting windows do not guarantee complete collection coverage.
Configuration observations do not prove an event's external destination port.

Earlier script versions remain for development history.
Use deploy.sh and report.sh as the current entry points.
