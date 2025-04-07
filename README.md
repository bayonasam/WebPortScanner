# WebPortScanner

A fast and flexible scanner to detect HTTP and HTTPS services across multiple ports — ideal for red teamers and recon workflows.

---

## 🔍 Why this tool?

Some firewalls or WAFs are configured to **fake responses** to tools like `nmap`, making ports appear closed or filtered when they’re actually open and serving web content.

This script was built out of that exact need:  
➡️ **To verify web services by making real HTTP/HTTPS requests**, not relying on low-level TCP behavior.

---

## 🚀 Features

- 🌐 Probes both HTTP and HTTPS
- 🎯 Works on single IPs, CIDRs, or files with multiple targets
- ⚙️ Custom or predefined port sets (`short`, `medium`, `large`)
- 📥 Handles invalid certificates silently (like most browsers)
- 📤 Outputs full URLs for tools like `gowitness`, `aquatone`, `eyewitness`
- 🧵 Multi-threaded for performance
- 📄 Outputs in RAW, CSV, and JSON formats

---

## 🛠️ Usage

### Scan a single IP or CIDR block
```bash
python scanner.py --target 192.168.1.0/24
```

### Scan targets from a file
```bash
python scanner.py --targetfile targets.txt --medium
```

### Custom ports and full output
```bash
python scanner.py -tf targets.txt --ports 8080,8180 --timeout 2 --threads 200 \
  --output raw.txt --csv report.csv --json report.json
```

---

## 🎯 Port Presets

| Flag       | Ports Included                                                                                  |
|------------|--------------------------------------------------------------------------------------------------|
| `--short`  | `80, 443, 8080, 8443`                                                                            |
| `--medium` | Includes short + `81, 90, 591, 3000, 3128, 8000, 8008, 8081, 8082, 8834, 8888, 7015, 8800, 8990, 10000` |
| `--large`  | Includes medium + `300, 2082, 2087, 2095, 4243, 4993, 5000, 7000, 7171, 7396, 7474, 8090, 8280, 8880, 9443` |

You can also provide your own `--ports`. Duplicates are automatically removed.

---

## 🧪 Output Examples

**RAW:**
```
HTTP://192.168.1.10:80  (200)  Server: nginx
HTTPS://192.168.1.10:443  (302)  Server: Apache
```

**CSV:**
```csv
ip,port,protocol,status_code,server,url
192.168.1.10,80,http,200,nginx,http://192.168.1.10:80
```

**JSON:**
```json
[
  {
    "ip": "192.168.1.10",
    "port": 80,
    "protocol": "http",
    "status_code": 200,
    "server": "nginx",
    "url": "http://192.168.1.10:80"
  }
]
```
