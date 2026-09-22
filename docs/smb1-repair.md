# Pinned Dionaea SMB1 repair

The lab's pinned Dionaea image accepts SMB TCP connections but its SMB1
negotiation handler raises `KeyError: 'OemDomainName'`. The response definition
uses `OemDomainNam` in two places while the handler uses `OemDomainName`.
The image separately rejects the tested SMB2/SMB3 negotiation packet.

When SMB is selected, chart preparation now includes an init container using
the same Dionaea image reference as the main container. It verifies the exact
source SHA-256, fixes the two field-name references, and writes the corrected
file to an emptyDir volume. The main container mounts this file read-only at
its original Python module path. A ConfigMap carries the repair script; its
hash is part of the ConfigMap name and pod volume reference. Every new pod
recreates the repair. No container image or persistent database is edited.
Only charts selecting SMB receive the repair. Unfamiliar source is refused;
an init failure prevents the application containers from starting. Inspect
`kubectl logs ... -c repair-dionaea-smb1` if rollout fails. The main deployment
uses Recreate, so an upgrade briefly interrupts its HTTP/HTTPS/SSH/SMB listeners.

This repairs SMB1 negotiation. It does not add SMB2/SMB3, prove successful
authentication/file operations, or establish exact target emulation. Discovery
of a modern SMB target can still select this limited SMB1 emulator. Do not
change the target Samba server to enable SMB1. Use an isolated lab client to
validate the emulator's actual supported dialect.

Offline checks reproduce the original exception from the collected image
source, then run that source's negotiation method with the repair. They check
serialized SMB1 replies with and without extended security, field lengths,
status, selected dialect and message ID. Other checks cover unexpected image
source, unchanged input files, chart selection and repair asset integrity.
They do not execute the image's Python 3.6/C networking runtime. The subsequent
live test negotiated NT LM 0.12 (SMBv1), and both probe connections matched
server records. HTTP/HTTPS/SSH/Modbus regression and the tested outbound-policy
checks also passed. See [protocol validation](protocol-validation.md). Repeat
acceptance on another installation; these results do not establish SMB2/SMB3 support.

Source and image provenance: `assets/dionaea-smb/manifest.json`.
The regression fixture retains its original copyright and license notices.
