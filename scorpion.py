"""Scorpion MultiTool - Terminal-based multi-tool for scammer defense and OSINT.

Features:
1. GeoIP Lookup using ipinfo.io
2. Local Device Scanner
3. Reverse Phone Lookup via Twilio Lookup V2 API
4. TCP Port Scanner with optional Shodan fallback
5. WHOIS Domain Lookup
6. Email Validator
"""

from __future__ import annotations

import asyncio
import os
import platform
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
import psutil
import dns.resolver
from dotenv import load_dotenv, find_dotenv
from rich import print
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from whois import query as whois_query

SCORPION_ART = r"""
      /\     /\
     ((\-\_/\-))
      )       (
     /         \
    (  )   (  )
   /\ |\_/| /\
  (  \|   |/  )
   \  |   |  /
    \ |   | /
     \|   |/
      `---`
"""

console = Console()


def banner() -> None:
    console.print(Panel.fit(SCORPION_ART, title="SCORPION MultiTool", subtitle="Stay safe out there", style="bold green"))


async def geoip_lookup() -> None:
    ip = Prompt.ask("Enter IP address")
    url = f"https://ipinfo.io/{ip}/json"
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            console.print(f"[red]Error fetching geoip data: {e}")
            return

    fields = ("ip", "hostname", "city", "region", "country", "loc", "org", "postal", "timezone")
    table = Table(title=f"GeoIP Info for {ip}")
    table.add_column("Field")
    table.add_column("Value")
    for key in fields:
        table.add_row(key.capitalize(), str(data.get(key, "N/A")))
    console.print(table)


def local_device_scanner() -> None:
    table = Table(title="Local Device Info")
    table.add_column("Property")
    table.add_column("Value", overflow="fold")

    table.add_row("Hostname", socket.gethostname())
    table.add_row("OS", f"{platform.system()} {platform.release()}")
    table.add_row("CPU Cores", str(psutil.cpu_count(logical=True)))
    table.add_row("Memory", f"{psutil.virtual_memory().total // (1024**2)} MB")
    connections = psutil.net_connections(kind="inet")
    table.add_row("Open Connections", str(len(connections)))
    console.print(table)

    if Confirm.ask("Show connection states (debug mode)?"):
        state_table = Table(title="Active Connection States")
        state_table.add_column("Local Address")
        state_table.add_column("State")
        for conn in connections:
            if conn.laddr:
                state_table.add_row(str(conn.laddr), conn.status)
        console.print(state_table)


async def twilio_lookup() -> None:
    phone = Prompt.ask("Enter phone number (in E.164 or national format)")
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    if not account_sid or not auth_token:
        console.print("[red]Twilio credentials missing. Set TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN.")
        return

    include_lti = Prompt.ask("Include line type intelligence? (y/n)", choices=["y", "n"], default="n")
    extra = "?Fields=line_type_intelligence,caller_name" if include_lti == "y" else "?Fields=caller_name"
    url = f"https://lookups.twilio.com/v2/PhoneNumbers/{phone}{extra}"

    async with httpx.AsyncClient(auth=(account_sid, auth_token)) as client:
        try:
            resp = await client.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            console.print(f"[red]Error contacting Twilio: {e}")
            return

    table = Table(title=f"Twilio Lookup for {phone}")
    for key in ["calling_country_code", "country_code", "phone_number", "national_format", "valid"]:
        table.add_row(key, str(data.get(key)))
    if data.get("caller_name"):
        table.add_row("Caller Name", data["caller_name"].get("caller_name", "Unknown"))
    lti = data.get("line_type_intelligence")
    if lti:
        for k, v in lti.items():
            table.add_row(f"line_type_{k}", str(v))
    console.print(table)


def tcp_port_scanner() -> None:
    ip = Prompt.ask("Enter IP to scan")
    full_scan = Confirm.ask("Scan full port range (1-1024)?", default=False)
    ports_to_scan = range(1, 1025) if full_scan else [22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]

    console.print(f"[yellow]Scanning {ip}...")

    def scan_port(target_ip: str, port: int) -> tuple[int, bool]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                result = s.connect_ex((target_ip, port))
                return port, result == 0
        except Exception:
            return port, False

    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports_to_scan}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)

    table = Table(title=f"Open Ports on {ip}")
    table.add_column("Port", justify="right")
    table.add_column("Status", style="green")

    if open_ports:
        for port in sorted(open_ports):
            table.add_row(str(port), "Open")
        console.print(table)
    else:
        console.print(f"[red]No open ports found on {ip}.[/red]")
        console.print("[yellow]⚠️ Remote scans might be blocked by firewalls. Test locally first if unsure.")
        if Confirm.ask("Try Shodan lookup for public IP?", default=True):
            shodan_api_key = os.getenv("SHODAN_API_KEY")
            if not shodan_api_key:
                console.print("[red]Missing SHODAN_API_KEY in .env file.")
                return
            if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
                console.print("[red]Shodan does not support private IPs.")
                return
            try:
                resp = httpx.get(f"https://api.shodan.io/shodan/host/{ip}?key={shodan_api_key}", timeout=10)
                resp.raise_for_status()
                data = resp.json()
                shodan_table = Table(title=f"Shodan Results for {ip}")
                shodan_table.add_column("Port")
                shodan_table.add_column("Service")
                for item in data.get("data", []):
                    shodan_table.add_row(str(item.get("port")), item.get("product", "Unknown"))
                console.print(shodan_table)
            except Exception as e:
                console.print(f"[red]Shodan lookup failed: {e}")


def whois_lookup() -> None:
    domain = Prompt.ask("Enter domain name")
    try:
        w = whois_query(domain)
        table = Table(title=f"WHOIS for {domain}")
        for key, value in w.__dict__.items():
            if key in ("domain_name", "registrar", "creation_date", "expiration_date", "name_servers"):
                table.add_row(key, str(value))
        console.print(table)
    except Exception as e:
        console.print(f"[red]WHOIS lookup failed: {e}")


def email_validator() -> None:
    email = Prompt.ask("Enter email to validate")
    regex = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    valid_format = re.match(regex, email) is not None
    table = Table(title=f"Email Validation for {email}")
    table.add_column("Check")
    table.add_column("Result")
    table.add_row("Format Valid", str(valid_format))

    domain = email.split("@")[-1]
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        table.add_row("MX Records Found", str(bool(mx_records)))
    except Exception:
        table.add_row("MX Records Found", "False")
    console.print(table)


async def main() -> None:
    load_dotenv(find_dotenv())
    while True:
        banner()
        console.print("1. GeoIP Lookup")
        console.print("2. Local Device Scanner")
        console.print("3. Reverse Phone Lookup [Twilio]")
        console.print("4. TCP Port Scanner")
        console.print("5. WHOIS Domain Lookup")
        console.print("6. Email Validator")
        console.print("7. Exit")
        choice = Prompt.ask("Choose an option", choices=["1", "2", "3", "4", "5", "6", "7"])
        console.clear()
        if choice == "1":
            await geoip_lookup()
        elif choice == "2":
            local_device_scanner()
        elif choice == "3":
            await twilio_lookup()
        elif choice == "4":
            tcp_port_scanner()
        elif choice == "5":
            whois_lookup()
        elif choice == "6":
            email_validator()
        else:
            break
        Prompt.ask("Press enter to return to menu")
        console.clear()


if __name__ == "__main__":
    asyncio.run(main())
