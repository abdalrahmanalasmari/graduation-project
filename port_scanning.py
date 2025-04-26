import nmap
from datetime import datetime

def scan_target(target, scan_type='normal', port_range=""):
    nm = nmap.PortScanner()
    result = ""
    try:
        if scan_type.lower() == 'aggressive':
            arguments = "-A"
        else:
            arguments = "-Pn"
        if port_range:
            arguments += f" -p {port_range}"
        result += f"Starting port scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        nm.scan(hosts=target, arguments=arguments)
        for host in nm.all_hosts():
            result += f"port scan report for {host}\n"
            closed_ports = [port for port in nm[host]['tcp'] if nm[host]['tcp'][port]['state'] == 'closed']
            if closed_ports:
                result += f"Not shown: {len(closed_ports)} closed tcp ports (reset)\n"
            if 'tcp' in nm[host]:
                result += "\nPORT     STATE SERVICE       VERSION\n"
                result += "-" * 40 + "\n"
                for port in nm[host]['tcp']:
                    port_info = nm[host]['tcp'][port]
                    version_info = f"{port_info.get('product', '')} {port_info.get('version', '')}".strip()
                    if not version_info:
                        version_info = "?"
                    result += "{:<8} {:<6} {:<16} {}\n".format(f"{port}/tcp", port_info['state'], port_info['name'], version_info)
            if 'osmatch' in nm[host]:
                result += "\nOS details:\n"
                for osmatch in nm[host]['osmatch']:
                    result += f"{osmatch['name']} (Accuracy: {osmatch['accuracy']}%)\n"
            if 'distance' in nm[host]:
                result += f"\nNetwork Distance: {nm[host]['distance']} hops\n"
    except Exception as e:
        result += f"Error: {e}\n"
    return result

if __name__ == "__main__":
    target = input("Enter the target IP or hostname: ")
    scan_type = input("Choose scan type (normal/aggressive): ").strip().lower()
    port_range = input("Enter port range (optional): ").strip()
    print(scan_target(target, scan_type, port_range))
