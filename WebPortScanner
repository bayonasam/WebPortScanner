import requests
import ipaddress
import argparse
import urllib3
import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.exceptions import RequestException, SSLError, ConnectionError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

found_services = []

# Define port sets hierarchically to avoid repetition
short_ports = [80, 443, 8080, 8443]
medium_ports = short_ports + [81, 90, 591, 3000, 3128, 8000, 8008, 8081, 8082, 8834, 8888, 7015, 8800, 8990, 10000]
large_ports = medium_ports + [300, 2082, 2087, 2095, 4243, 4993, 5000, 7000, 7171, 7396, 7474, 8090, 8280, 8880, 9443]

PORT_SETS = {
    "short": short_ports,
    "medium": medium_ports,
    "large": large_ports
}

def check_port(host, ports, timeout=3):
    protocols = ['http', 'https']
    results = []
    for port in ports:
        for protocol in protocols:
            url = f"{protocol}://{host}:{port}"
            try:
                response = requests.get(url, timeout=timeout, verify=False)
                server = response.headers.get("Server", "Unknown")
                results.append({
                    "ip": host,
                    "port": port,
                    "protocol": protocol,
                    "status_code": response.status_code,
                    "server": server,
                    "url": url
                })
            except (SSLError, ConnectionError, RequestException):
                pass
    return results

def scan_ip(ip, ports, timeout):
    print(f"[>] Scanning {ip}")
    res = check_port(str(ip), ports, timeout)
    if res:
        for r in res:
            print(f"  [+] {r['url']} - {r['status_code']} - {r['server']}")
        found_services.extend(res)

def parse_targets_from_file(file_path):
    targets = []
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                targets.extend(parse_targets(line))
    return targets

def parse_targets(target_str):
    try:
        network = ipaddress.ip_network(target_str, strict=False)
        return list(network.hosts())
    except ValueError:
        try:
            return [ipaddress.ip_address(target_str)]
        except ValueError:
            print(f"[!] Invalid address: {target_str}")
            return []

def save_results_raw(filename, results):
    with open(filename, 'w') as f:
        for s in results:
            line = f"{s['url'].upper()}  ({s['status_code']})  Server: {s['server']}\n"
            f.write(line)

def save_results_csv(filename, results):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['ip', 'port', 'protocol', 'status_code', 'server', 'url']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for s in results:
            writer.writerow(s)

def save_results_json(filename, results):
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fast web service port scanner")
    parser.add_argument("-t", "--target", help="Single IP or network in CIDR format (e.g. 192.168.1.10 or 192.168.1.0/24)")
    parser.add_argument("-tf", "--targetfile", help="File with list of IPs or CIDRs (one per line)")
    parser.add_argument("-p", "--ports", help="Ports to scan, comma-separated")
    parser.add_argument("--short", action="store_true", help=f"Use short predefined port list: {short_ports}")
    parser.add_argument("--medium", action="store_true", help=f"Use medium predefined port list (includes short): {medium_ports}")
    parser.add_argument("--large", action="store_true", help=f"Use large predefined port list (includes medium and short): {large_ports}")
    parser.add_argument("--threads", type=int, default=100, help="Number of concurrent requests (default: 100)")
    parser.add_argument("--timeout", type=int, default=3, help="Timeout per request in seconds (default: 3)")
    parser.add_argument("-o", "--output", help="Output file for RAW format results")
    parser.add_argument("--csv", help="Output file for CSV format results")
    parser.add_argument("--json", help="Output file for JSON format results")

    args = parser.parse_args()

    if not args.target and not args.targetfile:
        parser.error("You must specify at least --target or --targetfile")

    if sum([args.short, args.medium, args.large]) > 1:
        parser.error("You can only use one of --short, --medium, or --large at the same time")

    ports = set()
    if args.ports:
        try:
            ports.update(int(p.strip()) for p in args.ports.split(","))
        except ValueError:
            parser.error("Invalid port format. Use something like: 8080,8180")

    if args.large:
        ports.update(large_ports)
    elif args.medium:
        ports.update(medium_ports)
    elif args.short:
        ports.update(short_ports)

    if not ports:
        ports.update(short_ports)

    ports = sorted(ports)

    targets = []
    if args.target:
        targets.extend(parse_targets(args.target))
    if args.targetfile:
        targets.extend(parse_targets_from_file(args.targetfile))

    print(f"\n🔍 Starting scan of {len(targets)} host(s) on ports {ports} with timeout {args.timeout}s...\n")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_ip, ip, ports, args.timeout) for ip in targets]
        for _ in as_completed(futures):
            pass

    print("\n✅ Scan complete.")
    if found_services:
        print("\n📋 Services found:")
        for s in found_services:
            print(f" - {s['url'].upper()}  ({s['status_code']})  Server: {s['server']}")

        if args.output:
            save_results_raw(args.output, found_services)
            print(f"\n💾 RAW results saved to: {args.output}")

        if args.csv:
            save_results_csv(args.csv, found_services)
            print(f"📄 CSV results saved to: {args.csv}")

        if args.json:
            save_results_json(args.json, found_services)
            print(f"🧾 JSON results saved to: {args.json}")
    else:
        print("\n❌ No active services found on the specified ports.")
