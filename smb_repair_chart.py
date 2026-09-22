"""Generate a persistent, source-checked repair for the pinned SMB1 image."""
import hashlib
import json
from pathlib import Path

ASSETS = Path(__file__).resolve().parent / 'assets/dionaea-smb'
TARGET = '/opt/dionaea/lib/dionaea/python/dionaea/smb/include/smbfields.py'


def repair_assets(chart):
    script = (ASSETS / 'repair.py').read_bytes()
    manifest = json.loads((ASSETS / 'manifest.json').read_text())
    digest = hashlib.sha256(script).hexdigest()
    if digest != manifest['repair_script_sha256']:
        raise ValueError('SMB repair asset checksum mismatch.')
    # Changing the script changes the pod template and ConfigMap reference.
    config_name = '{{ .Release.Name }}-smb1-' + digest[:12]
    init = '''      initContainers:
        - name: repair-dionaea-smb1
          image: "{{ .Values.honeypots.dionaea.image.repository }}:{{ .Values.honeypots.dionaea.image.tag }}"
          imagePullPolicy: {{ .Values.honeypots.dionaea.image.pullPolicy }}
          command: ["python3", "-B", "/smb-repair/repair.py"]
          securityContext:
            runAsUser: 0
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: dionaea-smb-repair-script
              mountPath: /smb-repair
              readOnly: true
            - name: dionaea-smb-repaired
              mountPath: /smb-repaired
'''
    volumes = '''        - name: dionaea-smb-repair-script
          configMap:
            name: ''' + config_name + '''
            defaultMode: 0444
        - name: dionaea-smb-repaired
          emptyDir: {}
'''
    mount = '\n            - mountPath: ' + TARGET + '''
              name: dionaea-smb-repaired
              subPath: smbfields.py
              readOnly: true'''
    config = '''apiVersion: v1
kind: ConfigMap
metadata:
  name: ''' + config_name + '''
data:
  repair.py: |
{{ .Files.Get "files/dionaea-smb/repair.py" | indent 4 }}
'''
    outputs = {
        chart / 'files/dionaea-smb/repair.py': script,
        chart / 'files/dionaea-smb/manifest.json': (ASSETS / 'manifest.json').read_bytes(),
        chart / 'templates/dionaea-smb-repair.yaml': config.encode(),
    }
    return init, volumes, mount, outputs
