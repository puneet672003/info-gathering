import os
import socket
import whois
import dns.resolver
import requests
import pyfiglet
from rich import print
from rich.console import Console
from rich.table import Table
import nmap

IPINFO_API_URL = "https://ipinfo.io/{}/json"

console = Console()


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


class InfoGatheringTool:
    def __init__(self, domain):
        self.domain = domain
        self.ip_address = self.get_ip_address(domain)

    def get_ip_address(self, domain):
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return "Invalid domain"

    def get_whois_info(self):
        try:
            return whois.whois(self.domain)
        except Exception as e:
            return f"Error fetching WHOIS data: {e}"

    def get_dns_records(self):
        records = {}
        try:
            records["A"] = dns.resolver.resolve(self.domain, "A")
            records["MX"] = dns.resolver.resolve(self.domain, "MX")
            records["CNAME"] = dns.resolver.resolve(self.domain, "CNAME")
        except Exception as e:
            return str(e)
        return records

    def get_ip_geolocation(self):
        if not self.ip_address or self.ip_address == "Invalid domain":
            return None
        try:
            response = requests.get(IPINFO_API_URL.format(self.ip_address))
            return response.json()
        except Exception as e:
            return f"Error fetching geolocation data: {e}"

    def perform_nmap_scan(self):
        nm = nmap.PortScanner()
        try:
            nm.scan(self.ip_address, arguments="-sS")
            return nm[self.ip_address]
        except Exception as e:
            return f"Error performing nmap scan: {e}"

    def display_geolocation(self, geolocation):
        table = Table(title="Geolocation Information")
        table.add_column("Key", style="cyan", no_wrap=True)
        table.add_column("Value", style="magenta")

        for key, value in geolocation.items():
            table.add_row(key, str(value))

        console.print(table)

    def display_whois_info(self, whois_info):
        table = Table(title="WHOIS Information")
        table.add_column("Key", style="cyan", no_wrap=True)
        table.add_column("Value", style="magenta")

        for key, value in whois_info.items():
            if isinstance(value, list):
                value_str = ", ".join(str(v) for v in value)
            elif value is None:
                value_str = "N/A"
            else:
                value_str = str(value)

            table.add_row(key, value_str)

        console.print(table)

    def display_dns_records(self, dns_records):
        table = Table(title="DNS Records")
        table.add_column("Record Type", style="cyan", no_wrap=True)
        table.add_column("Records", style="magenta")

        for record_type, records in dns_records.items():
            record_str = ", ".join(str(record) for record in records)
            table.add_row(record_type, record_str)

        console.print(table)

    def gather_info(self):
        console.print(f"[bold green]Domain:[/bold green] {self.domain}")
        console.print(f"[bold green]IP Address:[/bold green] {self.ip_address}")

        geolocation = self.get_ip_geolocation()
        if geolocation:
            self.display_geolocation(geolocation)

        whois_info = self.get_whois_info()
        if isinstance(whois_info, dict):
            self.display_whois_info(whois_info)
        else:
            console.print(f"[bold red]WHOIS Error:[/bold red] {whois_info}")

        dns_records = self.get_dns_records()
        if isinstance(dns_records, dict):
            self.display_dns_records(dns_records)
        else:
            console.print(f"[bold red]DNS Records Error:[/bold red] {dns_records}")

        nmap_info = self.perform_nmap_scan()
        if isinstance(nmap_info, dict):
            console.print("[bold blue]Nmap Scan Results:[/bold blue]")
            for proto in nmap_info.all_protocols():
                console.print(f"Protocol: {proto}")
                lport = nmap_info[proto].keys()
                for port in lport:
                    console.print(
                        f"Port: {port}\tState: {nmap_info[proto][port]['state']}"
                    )
        else:
            console.print(f"[bold red]Nmap Error:[/bold red] {nmap_info}")


if __name__ == "__main__":
    clear_screen()
    title = pyfiglet.figlet_format("Information Gathering tool")
    print(title)

    domain_to_query = input("Enter a domain to gather information: ")
    tool = InfoGatheringTool(domain_to_query)
    tool.gather_info()
