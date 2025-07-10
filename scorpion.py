"""Scorpion MultiTool - Terminal-based multi-tool for scammer defense.

Features:
1. GeoIP Lookup using ipinfo.io
2. Local Device Scanner
3. Reverse Phone Lookup via Twilio Lookup V2 API
"""

from __future__ import annotations

import asyncio
import os
import platform
import socket
from typing import Any

import httpx
import psutil
from rich import print
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from dotenv import load_dotenv


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

    table = Table(title=f"GeoIP Info for {ip}")
    table.add_column("Field")
    table.add_column("Value")
    for key in ("city", "region", "country", "org"):
        table.add_row(key.capitalize(), data.get(key, "N/A"))
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


async def twilio_lookup() -> None:
    phone = Prompt.ask("Enter phone number (in E.164 or national format)")
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    if not account_sid or not auth_token:
        console.print("[red]Twilio credentials missing. Set TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN.")
        return

    fields = Prompt.ask("Include line type intelligence? (y/n)", choices=["y", "n"], default="n")
    url = f"https://lookups.twilio.com/v2/PhoneNumbers/{phone}"
    if fields == "y":
        url += "?Fields=line_type_intelligence"

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
    lti = data.get("line_type_intelligence")
    if lti:
        for k, v in lti.items():
            table.add_row(f"line_type_{k}", str(v))
    console.print(table)


async def main() -> None:
    load_dotenv()
    while True:
        banner()
        console.print("1. GeoIP Lookup")
        console.print("2. Local Device Scanner")
        console.print("3. Reverse Phone Lookup [Twilio]")
        console.print("4. Exit")
        choice = Prompt.ask("Choose an option", choices=["1", "2", "3", "4"])
        if choice == "1":
            await geoip_lookup()
        elif choice == "2":
            local_device_scanner()
        elif choice == "3":
            await twilio_lookup()
        else:
            break
        Prompt.ask("Press enter to continue")
        console.clear()


if __name__ == "__main__":
    asyncio.run(main())

