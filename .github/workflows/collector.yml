import requests
import ipaddress

def aggregate_cidrs(ip_list):
    networks = [ipaddress.ip_network(ip, strict=False) for ip in ip_list]
    return [str(net) for net in ipaddress.collapse_addresses(networks)]

def get_prefixes_from_asn(asn):
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}&latest=true"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    data = r.json()
    return [p['prefix'] for p in data.get('data', {}).get('prefixes', [])]

def get_oracle():
    r = requests.get("https://docs.oracle.com/iaas/tools/public_ip_ranges.json", timeout=30)
    data = r.json()
    ips = []
    for region in data['regions']:
        for cidr in region['cidrs']:
            ips.append(cidr['cidr'])
    return ips

def get_aws():
    r = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=30)
    data = r.json()
    return [p['ip_prefix'] for p in data['prefixes']]

def validate_ip(ip_str):
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except:
        return False

asn_providers = {
    'scaleway': 12876,
    'hetzner': 24940,
    'akamai': 20940,
    'digitalocean': 14061,
    'datacamp': 60068,
    'contabo': 51167,
    'ovh': 16276,
    'constant': 20473,
    'cloudflare': 13335,
    'google': 15169,
    'fastly': 54113
}

ipv4 = []
ipv6 = []

for name, asn in asn_providers.items():
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

try:
    aws = get_aws()
    print(f"aws: {len(aws)} ranges")
    for p in aws:
        if not validate_ip(p):
            continue
        if ':' in p:
            ipv6.append(p)
        else:
            ipv4.append(p)
except Exception as e:
    print(f"Error aws: {e}")

try:
    oracle = get_oracle()
    print(f"oracle: {len(oracle)} ranges")
    for p in oracle:
        if not validate_ip(p):
            continue
        if ':' in p:
            ipv6.append(p)
        else:
            ipv4.append(p)
except Exception as e:
    print(f"Error oracle: {e}")

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
