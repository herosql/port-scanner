import socket
import nmap
import ipaddress
from common_ports import ports_and_services
import re
# Linux install nmap
# pip install namp
def get_domain_by_ip(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def check_and_get_ip(host):
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError as e:
        ip_address_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

        if re.match(domain_pattern, host):
            try:
                ip = socket.gethostbyname(host)
                return ip
            except socket.gaierror:
                return None
        elif re.match(ip_address_pattern, host) is None:
            return False
        else:
            return False



def get_open_ports(target, port_range, verbose = False):
    ip = check_and_get_ip(target)
    if ip is None:
        return 'Error: Invalid hostname'
    if ip is False:
        return 'Error: Invalid IP address'
    open_ports = []
    nm = nmap.PortScanner()
    result_list = [str(num) for num in range(port_range[0], port_range[1] + 1)]
    portsStr = ",".join(result_list)
    # result = nm.scan(target, portsStr)
    result = nm.scan(ip, portsStr)
    tcp_ports = result['scan'][ip]['tcp']
    if verbose:
        # result = f"Open ports for {target} ({ip})\nPORT     SERVICE\n"
        result = ""
        if ip == target:
            host = get_domain_by_ip(ip)
            if host is None:
                result = f"Open ports for {target}\nPORT     SERVICE\n"
            else:
                result = f"Open ports for {host} ({ip})\nPORT     SERVICE\n"

        else:
            result = f"Open ports for {target} ({ip})\nPORT     SERVICE\n"
        for port in tcp_ports:
            if tcp_ports[port]['state'] == 'open':
                serviceName = ports_and_services.get(port)
                result += f"{str(port).ljust(9)}{serviceName}\n"
        return result.rstrip()

    else:
        for port in tcp_ports:
            if tcp_ports[port]['state'] == 'open':
                open_ports.append(port)
        return open_ports