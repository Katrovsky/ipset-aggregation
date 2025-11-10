import requests
import ipaddress

def aggregate_cidrs(ip_list):
    networks = [ipaddress.ip_network(ip, strict=False) for ip in ip_list]
    return [str(net) for net in ipaddress.collapse_addresses(networks)]

def get_prefixes_from_asn(asn):
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    data = r.json()
    return [p['prefix'] for p in data.get('data', {}).get('prefixes', [])]

def validate_ip(ip_str):
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except:
        return False

providers = {
    'scaleway': 12876,
    'hetzner': 24940,
    'akamai': 20940,
    'digitalocean': 14061,
    'datacamp': 60068,
    'contabo': 51167,
    'ovh': 16276,
    'constant': 20473,
    'cloudflare': 13335,
    'oracle': 31898,
    'amazon': 16509,
    'google': 15169,
    'fastly': 54113
}

ipv4 = []
ipv6 = []

for name, asn in providers.items():
    try:
        prefixes = get_prefixes_from_asn(asn)
        print(f"{name}: {len(prefixes)} ranges")
        for p in prefixes:
            if not validate_ip(p):
                continue
            if ':' in p:
                ipv6.append(p)
            else:
                ipv4.append(p)
    except Exception as e:
        print(f"Error {name}: {e}")

print(f"Before aggregation: IPv4: {len(ipv4)}, IPv6: {len(ipv6)}")

ipv4_aggregated = aggregate_cidrs(ipv4)
ipv6_aggregated = aggregate_cidrs(ipv6)

print(f"After aggregation: IPv4: {len(ipv4_aggregated)}, IPv6: {len(ipv6_aggregated)}")

with open('ipset-all-ipv4.txt', 'w') as f:
    f.write('\n'.join(sorted(ipv4_aggregated)))
with open('ipset-all-ipv6.txt', 'w') as f:
    f.write('\n'.join(sorted(ipv6_aggregated)))
with open('ipset-all.txt', 'w') as f:
    f.write('\n'.join(sorted(ipv4_aggregated + ipv6_aggregated)))
