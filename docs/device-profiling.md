# Descriptive device profiling

Each discovered, responding host is described as a network-visible device. Two
independent questions are answered: what OS family does the evidence suggest,
and which functional roles are observed? A Linux host can be both an SSH server
and a web server. No physical device type or exact hardware model is assumed.

## Separation from deployment

`device_profile` is an additive field in the existing per-host profile and the
reconciled profile. It is descriptive only. `build_plan_v2.py` still reads the
confirmed service recommendations and unresolved service evidence; it does not
read OS classification, roles, identity metadata or confidence. A wrong inferred
classification cannot change selection. This is not a guarantee against errors
in service detection, catalog mappings, runtime recipes or software execution.

The legacy `profile` string remains a service summary for compatibility, and
the legacy `device_type` remains `undetermined`. The richer device description
lives in `device_profile`, with its own `schema_version: 1`. Existing outer
schema versions and deployment configuration formats remain unchanged.

## Output

| Field | Meaning |
| --- | --- |
| `os_family` | One inferred family, or `unknown` |
| `os_assessment.status` | `inferred`, `no_evidence`, `conflicting_evidence`, or `unrecognized_evidence` |
| `os_assessment.evidence` | Raw structured hints, interpretation, XML location and source index |
| `roles` | Zero or more functional roles; not mutually exclusive |
| `role_evidence` | Protocol, endpoint, source index and observation index for each role |
| `identity_observations` | Available addresses, MAC vendor labels and hostnames, retained per source |
| `physical_device_type` | `undetermined`; no PLC, printer or router classifier is implemented |
| `selection_effect` | `none` |

For example, an observed Linux SSH/web host may have `os_family: linux` and
`roles: [ssh_server, web_server]`. This is an inference from network evidence,
not independent proof of its installed operating system or physical identity.

OS assessment uses explicit Nmap `service@ostype`, recognized OS CPEs and any
supplied `osmatch/osclass@osfamily` evidence. Application CPEs, free-text product
names, hostnames and MAC vendors do not establish the host OS. The initial
normalization table covers Linux, Windows, several BSD families, macOS, Solaris,
Unix and Android hints; other values remain visible but unresolved.
Conflicting families produce `unknown`; unknown structured hints also prevent a
resolved assessment. A generic Unix hint is compatible with the explicitly
listed Unix-family systems, and an Android hint can specialize a Linux-kernel
hint. These are documented rules, not a trained or probabilistic model.

All hints are retained across the ordered scans. A family conflict does not
become a service conflict and does not block an otherwise supported service
plan. Real service/endpoint conflicts still retain their existing planning gate.
Nmap's reported fingerprint accuracy is preserved as source metadata, not
reinterpreted as an identification probability. Confidence is `not_calibrated`.

Roles use open, positively identified services, including supported dedicated
SMB/Modbus probe evidence. HTTP and HTTPS both contribute to `web_server`, with
separate endpoint evidence. SSH gives `ssh_server`; positively identified SMB
gives `smb_server`; identified Modbus gives `modbus_endpoint`. The descriptive
role table also covers FTP, SMTP/IMAP/POP3, DNS and SNMP when probed evidence is
supplied. Those roles do not add scan ports or honeypot recipes. Unknown services,
port-table guesses and unresolved endpoints do not get a role. Missing roles
mean no qualifying evidence within the supplied scan scope, not proven absence.

SMB does not establish Windows, and Modbus does not establish a PLC. In the lab,
the simulated Modbus target remains a Modbus-serving endpoint with an
undetermined physical device type. Proxying, virtual hosting, spoofed banners
and incomplete scans can make network-visible attributes differ from host reality.

## Reprocess saved evidence

The normal scanner automatically includes device profiles in new profile JSON.
Reconciliation combines them across the general and dedicated protocol scans.
This change adds no scan flags, OS probes, ports, dependencies or privileges.
In particular, it does not silently enable Nmap OS fingerprinting (`-O`).
An OS family may remain unknown when the existing scans provide no usable hint.

To inspect an already completed discovery run without rescanning or deploying:

```bash
python3 describe_devices.py \
  --evidence /path/to/run/system/discovery \
  --output /path/to/new-device-profile-directory
```

This reparses the original XML using its saved catalog/manifest and writes
`device-profiles.json` plus a short `device-profiles.txt` summary. Original scan
files and reports are unchanged. Existing output directories are refused. The
JSON includes source hashes, scan timestamps and detailed observations. It is
a discovery description, separate from the scheduled interaction reports.

## Evaluation and limits

Offline fixtures cover multiple roles, OS hints, OS conflicts, unknown evidence,
provenance, nonstandard web ports, positive protocol probes, and refusal to derive
OS from products or device type from protocol alone. Planning tests mutate or
remove descriptive classification while preserving service evidence and require
identical deployment decisions and generated requests. Unsupported service roles
remain unsupported for deployment. A read-only output test prevents overwrites.

These tests establish rule behavior, not measured classification accuracy on
real devices. For live evaluation, record ground truth separately (OS and enabled
service roles), run the profiler without reading those labels, and compare
correct, incorrect and unknown OS assessments plus role precision/recall within
the scanned scope. Include contradictory/insufficient evidence cases. A Linux
VM running a simulator does not establish performance on physical PLC hardware.
An initial saved-scan check passed on 23 September 2026:
192.168.77.20 was assessed as Linux with SSH, web and SMB roles;
192.168.77.21 was assessed as Linux with SSH and Modbus endpoint roles.
The roles agree with the configured lab services. Both OS assessments remain
inferences, and physical device types remain undetermined.
Evidence: protocol-workspace/runs/device-profile-review-Lw2dlzRg/profiles.
All 71 offline tests passed on thesis-repro.
This two-host check does not establish general classification accuracy;
broader evaluation against independently recorded ground truth remains pending.

References: [Nmap XML fields](https://nmap.org/book/nmap-dtd.html),
[Nmap OS output](https://nmap.org/book/osdetect-usage.html).
