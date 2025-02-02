#!/usr/bin/env python3 -tt
import argparse
import re
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument("ip_range", help="IP range to scan.")
args = parser.parse_args()
ip_range = args.ip_range


def scan_hosts(ip_range):
    print(" [+] Scanning for available hosts")
    host_results = str(
        subprocess.Popen(
            ["nmap", "-sn", ip_range], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ).communicate()[0]
    )[2:-3]
    available_hosts = re.findall(r"\(?([\d\.]+)\)?\\nHost is up ", host_results)
    return available_hosts


def scan_ports(available_hosts):
    host_ports = []
    all_ports = []
    print(
        " [+]  Available hosts found: {}".format(
            str(available_hosts)[2:-2].replace("', '", ", ")
        )
    )
    for host in available_hosts:
        print(" [+] Scanning for open ports on {}...".format(host))
        port_results = str(
            subprocess.Popen(
                ["nmap", "-T4", "-p-", host],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).communicate()[0]
        )[2:-3]
        open_ports = re.findall(r"\\n(\d+)\/[^ ]+\s+open", port_results)
        if len(open_ports) > 0:
            print(
                "   |  Ports {} open on {}".format(
                    str(open_ports)[2:-2].replace("', '", ", "), host
                )
            )
            for port in open_ports:
                host_ports.append(f"{host}::{port}")
                all_ports.append(port)
        else:
            print("   x  No results for {}.".format(host))

    return host_ports, str(sorted(list(set(all_ports))))[2:-2].replace("', '", ",")


def port_scan(ip_range, host_ports, all_ports):
    detailed_results = str(
        subprocess.Popen(
            [
                "nmap",
                "-T4",
                "-p",
                all_ports,
                "-A",
                ip_range,
                "-oA",
                ip_range.replace("/", "_"),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).communicate()[0]
    )[2:-3]
    print(
        f'\n [*] Finished. Full results are contained in {ip_range.replace("/", "_")}.*'
    )


def main():
    time.sleep(0.2)
    subprocess.Popen(["clear"])
    time.sleep(0.2)
    # host scanning
    available_hosts = scan_hosts(ip_range)
    # port and service scanning
    host_ports, all_ports = scan_ports(available_hosts)
    if len(all_ports) > 0:
        port_scan(ip_range, host_ports, all_ports)
    else:
        print(
            "      No ports open on any of the following hosts: {}.".format(
                available_hosts
            )
        )


if __name__ == "__main__":
    main()
