# Dionaea SMB regression fixture

`source.zip.b64` contains the unmodified SMB handler and four packet modules
collected from the pinned image documented in assets/dionaea-smb/manifest.json.
It is a source-only test fixture, not a replacement image. Original copyright
and SPDX notices are retained. Scapy-derived files are GPL-2.0-only; the other
Dionaea files are GPL-2.0-or-later. See COPYING for GPL version 2.

Tests import only the packet modules and extract the real handler's process
method. They do not start Dionaea or simulate its C networking layer.
