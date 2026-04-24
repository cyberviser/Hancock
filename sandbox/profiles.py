TOOL_PROFILES = {
    "nmap": {
        "image": "ghcr.io/cyberviser/hancock-nmap:latest",
        "entrypoint": "nmap",
        "network": "none",
        "cpus": "1",
        "memory": "512m",
        "timeout": 90,
        "volumes": [],
    },
    "sqlmap": {
        "image": "ghcr.io/cyberviser/hancock-sqlmap:latest",
        "entrypoint": "sqlmap",
        "network": "none",
        "cpus": "1",
        "memory": "512m",
        "timeout": 120,
        "volumes": [],
    },
}
