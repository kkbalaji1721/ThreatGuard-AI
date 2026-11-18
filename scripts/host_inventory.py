"""Read-only host inventory helper. Run directly on your own machine.
It does not scan ports, exploit vulnerabilities, change settings, or install patches."""
import platform, sys, json
from importlib.metadata import distributions
pkgs = []
for d in distributions():
    name = d.metadata.get("Name")
    if name:
        pkgs.append({"name": name, "version": d.version})
print(json.dumps({
    "scan_mode": "read-only",
    "system": platform.system(),
    "release": platform.release(),
    "version": platform.version(),
    "machine": platform.machine(),
    "python": sys.version.split()[0],
    "hostname": platform.node(),
    "python_packages": sorted(pkgs, key=lambda x: x["name"].lower())[:300],
    "note": "Inventory only. Package names/versions must be compared with authoritative vendor advisories; this script does not assert vulnerability."
}, indent=2))
