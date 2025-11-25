import requests
import ipaddress

def aggregate_cidrs(ip_list):
    if not ip_list:
        return []
    networks = [ipaddress.ip_network(ip, strict=False) for ip in ip_list]
    collapsed = list(ipaddress.collapse_addresses(networks))
    return [str(net) for net in collapsed]

def get_prefixes_from_asn(asn):
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    data = r.json()
    return [p['prefix'] for p in data.get('data', {}).get('prefixes', [])]

def get_oracle():
    r = requests.get("https://docs.oracle.com/iaas/tools/public_ip_ranges.json", timeout=30)
    r.raise_for_status()
    data = r.json()
    ips = []
    for region in data.get('regions', []):
        for cidr in region.get('cidrs', []):
            ips.append(cidr['cidr'])
    return ips

def get_aws():
    r = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=30)
    r.raise_for_status()
    data = r.json()
    ipv4 = [p['ip_prefix'] for p in data.get('prefixes', [])]
    ipv6 = [p['ipv6_prefix'] for p in data.get('ipv6_prefixes', [])]
    return ipv4 + ipv6

def get_google_cloud():
    r = requests.get("https://www.gstatic.com/ipranges/cloud.json", timeout=30)
    r.raise_for_status()
    data = r.json()
    ips = []
    for prefix in data.get('prefixes', []):
        if 'ipv4Prefix' in prefix:
            ips.append(prefix['ipv4Prefix'])
        if 'ipv6Prefix' in prefix:
            ips.append(prefix['ipv6Prefix'])
    return ips

def get_cloudflare():
    ipv4 = requests.get('https://www.cloudflare.com/ips-v4', timeout=30).text.strip().split('\n')
    ipv6 = requests.get('https://www.cloudflare.com/ips-v6', timeout=30).text.strip().split('\n')
    return [ip.strip() for ip in ipv4 + ipv6 if ip.strip()]

def validate_ip(ip_str):
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except:
        return False

asn_providers = {
    'scaleway': [12876, 29447, 54265, 202023],
    'hetzner': [24940, 213230, 212317],
    'akamai': [20940, 16625, 18680, 18717, 20189, 21342, 21357, 23454, 23903, 24319],
    'digitalocean': [14061, 46652, 62567, 135340, 393406, 394362],
    'cdn77': [60068],
    'contabo': [51167],
    'ovh': [16276],
    'constant_vultr': [20473],
    'fastly': [54113],
}

ipv4 = []
ipv6 = []

for name, asn_list in asn_providers.items():
    for asn in asn_list:
        try:
            prefixes = get_prefixes_from_asn(asn)
            print(f"{name} AS{asn}: {len(prefixes)} ranges")
            for p in prefixes:
                if not validate_ip(p):
                    continue
                if ':' in p:
                    ipv6.append(p)
                else:
                    ipv4.append(p)
        except Exception as e:
            print(f"Error {name} AS{asn}: {e}")

try:
    cloudflare = get_cloudflare()
    print(f"cloudflare (official): {len(cloudflare)} ranges")
    for p in cloudflare:
        if not validate_ip(p):
            continue
        if ':' in p:
            ipv6.append(p)
        else:
            ipv4.append(p)
except Exception as e:
    print(f"Error cloudflare: {e}")

try:
    google = get_google_cloud()
    print(f"google (official): {len(google)} ranges")
    for p in google:
        if not validate_ip(p):
            continue
        if ':' in p:
            ipv6.append(p)
        else:
            ipv4.append(p)
except Exception as e:
    print(f"Error google: {e}")

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

print(f"\nBefore aggregation: IPv4: {len(ipv4)}, IPv6: {len(ipv6)}")

ipv4_aggregated = aggregate_cidrs(ipv4)
ipv6_aggregated = aggregate_cidrs(ipv6)

print(f"After aggregation: IPv4: {len(ipv4_aggregated)}, IPv6: {len(ipv6_aggregated)}")
print(f"Reduction: IPv4: {len(ipv4) - len(ipv4_aggregated)} ({100*(len(ipv4)-len(ipv4_aggregated))/len(ipv4):.1f}%), IPv6: {len(ipv6) - len(ipv6_aggregated)} ({100*(len(ipv6)-len(ipv6_aggregated))/len(ipv6):.1f}%)")

with open('ipset-all-ipv4.txt', 'w') as f:
    f.write('\n'.join(sorted(ipv4_aggregated, key=lambda x: ipaddress.ip_network(x))))

with open('ipset-all-ipv6.txt', 'w') as f:
    f.write('\n'.join(sorted(ipv6_aggregated, key=lambda x: ipaddress.ip_network(x))))

with open('ipset-all.txt', 'w') as f:
    all_sorted = sorted(ipv4_aggregated + ipv6_aggregated, key=lambda x: (1 if ':' in x else 0, ipaddress.ip_network(x)))
    f.write('\n'.join(all_sorted))

print(f"\nFiles created:")
print(f"  ipset-all-ipv4.txt: {len(ipv4_aggregated)} ranges")
print(f"  ipset-all-ipv6.txt: {len(ipv6_aggregated)} ranges")
print(f"  ipset-all.txt: {len(ipv4_aggregated) + len(ipv6_aggregated)} ranges")
