import warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)

import requests
import socket
import ssl
import datetime
import dns.resolver
import whois
import pyfiglet
import time
import json

from colorama import Fore, Style, init
from rich import print
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track

init(autoreset=True)
console = Console()

def show_banner():
    banner = pyfiglet.figlet_format("GhostScan")
    print(f"[bold red]{banner}[/bold red]")
    print(f"[bold bright_cyan]💀 Welcome to [green]GhostScan[/green] - Hacker's Recon Tool 💀[/bold bright_cyan]")
    print("[magenta]" + "═" * 60 + "[/magenta]")
    time.sleep(1)

def check_subdomain(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False

def enumerate_subdomains(domain):
    console.print(f"[bold cyan]🔍 Enumerating subdomains for [green]{domain}[/green][/bold cyan]")
    common_subs = [
        "www", "mail", "ftp", "webmail", "smtp", "admin", "api", "blog",
        "dev", "portal", "test", "shop", "m", "ns1", "ns2", "email", "secure"
    ]
    live_subs = []
    dead_subs = []

    for sub in track(common_subs, description="📡 Scanning subdomains..."):
        full_domain = f"{sub}.{domain}"
        if check_subdomain(full_domain):
            live_subs.append(full_domain)
        else:
            dead_subs.append(full_domain)
    return live_subs, dead_subs

def get_dns_records(domain):
    records = {}
    try:
        for rtype in ["A", "MX", "TXT", "CNAME", "NS"]:
            answers = dns.resolver.resolve(domain, rtype, raise_on_no_answer=False)
            records[rtype] = [str(r) for r in answers]
    except:
        pass
    return records

def get_whois_info(domain):
    try:
        return whois.whois(domain)
    except:
        return None

def get_ip_geolocation(domain):
    try:
        ip = socket.gethostbyname(domain)
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if resp.status_code == 200:
            geo = resp.json()
            geo["ip"] = ip
            return geo
        else:
            return {"ip": ip}
    except:
        return {}

def get_http_headers(domain):
    try:
        resp = requests.get(f"http://{domain}", timeout=5)
        return dict(resp.headers)
    except:
        return {}

def get_ssl_info(domain):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                return {
                    "issuer": issuer.get("O", "N/A"),
                    "valid_from": cert.get("notBefore", "N/A"),
                    "valid_to": cert.get("notAfter", "N/A"),
                }
    except:
        return {}

# HTTP Fuzzing
def http_fuzzing(domain):
    console.print(f"[bold cyan]🔎 Starting HTTP Fuzzing on [green]{domain}[/green][/bold cyan]")
    common_paths = [
        "/", "/admin", "/login", "/dashboard", "/backup", "/config", "/hidden",
        "/secret", "/test", "/dev", "/api", "/uploads", "/old", "/private"
    ]
    found_paths = []
    for path in track(common_paths, description="🌐 Fuzzing paths..."):
        url = f"http://{domain}{path}"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code in [200, 301, 302, 403]:  # 403 means exists but forbidden
                found_paths.append((path, resp.status_code))
        except:
            continue
    return found_paths

def print_fuzzing_results(paths):
    table = Table(title="🔍 HTTP Fuzzing Results (Hidden Paths)")
    table.add_column("Path", style="cyan")
    table.add_column("Status Code", style="green")
    for path, code in paths:
        table.add_row(path, str(code))
    console.print(table)

# Banner Grabbing
def grab_banner(ip, port, timeout=3):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode(errors='ignore').strip()
        sock.close()
        return banner if banner else "No banner received"
    except Exception as e:
        return f"Failed to grab banner: {e}"

def banner_grabbing(domain):
    console.print(f"[bold cyan]🛡️ Starting Banner Grabbing on [green]{domain}[/green][/bold cyan]")
    ip = None
    try:
        ip = socket.gethostbyname(domain)
    except:
        return {}

    common_ports = [21, 22, 25, 80, 110, 143, 443, 3306]
    banners = {}
    for port in track(common_ports, description="🔌 Grabbing banners on ports..."):
        banner = grab_banner(ip, port)
        banners[port] = banner
    return banners

def print_banner_results(banners):
    table = Table(title="🛡️ Service Banner Grabbing Results")
    table.add_column("Port", style="magenta")
    table.add_column("Banner", style="yellow")
    for port, banner in banners.items():
        table.add_row(str(port), banner)
    console.print(table)

# Print functions for other data
def print_subdomains(live, dead):
    table = Table(title="🌐 Subdomain Scan Results")
    table.add_column("Status", style="bold")
    table.add_column("Subdomain", style="cyan")
    for sub in live:
        table.add_row("[green]LIVE[/green]", sub)
    for sub in dead:
        table.add_row("[red]DEAD[/red]", sub)
    console.print(table)

def print_dns(records):
    table = Table(title="📡 DNS Records")
    table.add_column("Type", style="magenta")
    table.add_column("Value", style="yellow")
    for rtype, vals in records.items():
        for val in vals:
            table.add_row(rtype, val)
    console.print(table)

def print_whois(w):
    if not w:
        console.print("[red]No WHOIS data available[/red]")
        return
    panel_text = ""
    attrs = ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'name_servers']
    for attr in attrs:
        val = getattr(w, attr, "N/A")
        if isinstance(val, list):
            val = ", ".join([str(v) for v in val])
        panel_text += f"[bold]{attr.replace('_',' ').title()}:[/bold] {val}\n"
    console.print(Panel(panel_text, title="WHOIS Information", style="green"))

def print_ip_geo(geo):
    if not geo:
        console.print("[red]No IP Geolocation info available[/red]")
        return
    panel_text = ""
    keys = ["ip", "city", "region", "country", "org", "loc"]
    for k in keys:
        if k in geo:
            panel_text += f"[bold]{k.title()}:[/bold] {geo[k]}\n"
    console.print(Panel(panel_text, title="IP Geolocation", style="cyan"))

def print_http_headers(headers):
    if not headers:
        console.print("[red]No HTTP headers available[/red]")
        return
    table = Table(title="📥 HTTP Headers")
    table.add_column("Header", style="magenta")
    table.add_column("Value", style="yellow")
    for k, v in headers.items():
        table.add_row(k, v)
    console.print(table)

def print_ssl_info(sslinfo):
    if not sslinfo:
        console.print("[red]No SSL certificate info available[/red]")
        return
    panel_text = f"[bold]Issuer:[/bold] {sslinfo.get('issuer')}\n"
    panel_text += f"[bold]Valid From:[/bold] {sslinfo.get('valid_from')}\n"
    panel_text += f"[bold]Valid To:[/bold] {sslinfo.get('valid_to')}\n"
    console.print(Panel(panel_text, title="🔐 SSL Certificate", style="blue"))

# Formatting report for TXT
def format_report(domain, data):
    report = f"=== GhostScan Report for {domain} ===\n\n"
    report += "\n".join([f"[LIVE] {s}" for s in data["Live Subdomains"]]) + "\n"
    report += "\n".join([f"[DEAD] {s}" for s in data["Dead Subdomains"]]) + "\n\n"
    for rtype, vals in data["DNS Records"].items():
        for val in vals:
            report += f"{rtype}: {val}\n"
    w = data["WHOIS"]
    if w:
        for attr in ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'name_servers']:
            val = getattr(w, attr, "N/A")
            if isinstance(val, list):
                val = ", ".join([str(v) for v in val])
            report += f"{attr}: {val}\n"
    geo = data["IP Geolocation"]
    for k in ["ip", "city", "region", "country", "org", "loc"]:
        if k in geo:
            report += f"{k}: {geo[k]}\n"
    for k, v in data["HTTP Headers"].items():
        report += f"{k}: {v}\n"
    sslinfo = data["SSL Info"]
    for k in ["issuer", "valid_from", "valid_to"]:
        report += f"{k}: {sslinfo.get(k)}\n"
    # HTTP Fuzzing results
    report += "\nHTTP Fuzzing Results:\n"
    for path, code in data.get("HTTP Fuzzing", []):
        report += f"{path} - Status: {code}\n"
    # Banner Grabbing results
    report += "\nBanner Grabbing Results:\n"
    for port, banner in data.get("Banner Grabbing", {}).items():
        report += f"Port {port}: {banner}\n"
    return report

def save_report(domain, data, filename):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            report_text = format_report(domain, data)
            f.write(report_text)
        console.print(f"[bold green]✔ Report saved to [yellow]{filename}[/yellow][/bold green]")
    except Exception as e:
        console.print(f"[red]❌ Error saving report: {e}[/red]")

def save_json_report(domain, data, filename):
    def whois_to_dict(whois_obj):
        if not whois_obj:
            return {}
        attrs = ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'name_servers']
        wdict = {}
        for attr in attrs:
            val = getattr(whois_obj, attr, None)
            if isinstance(val, list):
                val = [str(v) for v in val]
            elif isinstance(val, (datetime.date, datetime.datetime)):
                val = val.isoformat()
            wdict[attr] = val
        return wdict

    json_data = {
        "Live Subdomains": data["Live Subdomains"],
        "Dead Subdomains": data["Dead Subdomains"],
        "DNS Records": data["DNS Records"],
        "WHOIS": whois_to_dict(data["WHOIS"]),
        "IP Geolocation": data["IP Geolocation"],
        "HTTP Headers": data["HTTP Headers"],
        "SSL Info": data["SSL Info"],
        "HTTP Fuzzing": data.get("HTTP Fuzzing", []),
        "Banner Grabbing": data.get("Banner Grabbing", {})
    }

    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=4)
        console.print(f"[bold green]✔ JSON report saved to [yellow]{filename}[/yellow][/bold green]")
    except Exception as e:
        console.print(f"[red]❌ Error saving JSON report: {e}[/red]")

def main():
    show_banner()
    domain = console.input("[bold cyan]Enter the target domain:[/bold cyan] ").strip()

    live_subs, dead_subs = enumerate_subdomains(domain)
    dns_records = get_dns_records(domain)
    whois_info = get_whois_info(domain)
    ip_geo = get_ip_geolocation(domain)
    http_headers = get_http_headers(domain)
    ssl_info = get_ssl_info(domain)

    http_fuzz = http_fuzzing(domain)
    banners = banner_grabbing(domain)

    print_subdomains(live_subs, dead_subs)
    print_dns(dns_records)
    print_whois(whois_info)
    print_ip_geo(ip_geo)
    print_http_headers(http_headers)
    print_ssl_info(ssl_info)
    print_fuzzing_results(http_fuzz)
    print_banner_results(banners)

    data = {
        "Live Subdomains": live_subs,
        "Dead Subdomains": dead_subs,
        "DNS Records": dns_records,
        "WHOIS": whois_info,
        "IP Geolocation": ip_geo,
        "HTTP Headers": http_headers,
        "SSL Info": ssl_info,
        "HTTP Fuzzing": http_fuzz,
        "Banner Grabbing": banners
    }

    filename_base = console.input("[bold yellow]Enter base filename to save reports (without extension):[/bold yellow] ").strip()
    if not filename_base:
        filename_base = f"GhostScan_Report_{domain.replace('.', '_')}"

    txt_file = filename_base + ".txt"
    json_file = filename_base + ".json"

    save_report(domain, data, txt_file)
    save_json_report(domain, data, json_file)

if __name__ == "__main__":
    main()
