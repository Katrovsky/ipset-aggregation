import requests
import ipaddress
import re

def get_cloudflare():
    ips = []
    for url in ["https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"]:
        r = requests.get(url, timeout=10)
        ips.extend([ip.strip() for ip in r.text.split('\n') if ip.strip()])
    return ips

def get_digitalocean():
    r = requests.get("https://digitalocean.com/geo/google.csv", timeout=10)
    return [line.split(',')[0] for line in r.text.split('\n') if line and ',' in line]

def get_hetzner():
    r = requests.get("https://wiki.hetzner.de/index.php/Rechenzentren_und_IP-Bereiche/en", timeout=10)
    matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/\d{1,2})?\b', r.text)
    return list(set(matches))

def get_ovh():
    r = requests.get("https://docs.ovh.com/gb/en/network-ip/ipv4-ipv6/", timeout=10)
    matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/\d{1,2})?\b', r.text)
    return list(set(matches))

def get_oracle():
    r = requests.get("https://docs.oracle.com/iaas/tools/public_ip_ranges.json", timeout=10)
    data = r.json()
    ips = []
    for region in data['regions']:
        for cidr in region['cidrs']:
            ips.append(cidr['cidr'])
    return ips

def get_aws():
    r = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=10)
    data = r.json()
    return [p['ip_prefix'] for p in data['prefixes']]

def get_google():
    r = requests.get("https://www.gstatic.com/ipranges/cloud.json", timeout=10)
    data = r.json()
    return [p.get('ipv4Prefix', p.get('ipv6Prefix')) for p in data['prefixes']]

def get_fastly():
    r = requests.get("https://api.fastly.com/public-ip-list", timeout=10)
    data = r.json()
    return data['addresses'] + data['ipv6_addresses']

def get_akamai():
    r = requests.get("https://developer.akamai.com/api/cloud_security/ip_network_lists/v2.html", timeout=10)
    return []

def validate_ip(ip_str):
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except:
        return False

providers = {
    'cloudflare': get_cloudflare,
    'digitalocean': get_digitalocean,
    'hetzner': get_hetzner,
    'ovh': get_ovh,
    'oracle': get_oracle,
    'aws': get_aws,
    'google': get_google,
    'fastly': get_fastly,
    'akamai': get_akamai
}

ipv4 = []
ipv6 = []

for name, func in providers.items():
    try:
        ips = func()
        for ip in ips:
            if not validate_ip(ip):
                continue
            if ':' in ip:
                ipv6.append(ip)
            else:
                ipv4.append(ip)
    except Exception as e:
        print(f"Error {name}: {e}")

with open('ipset-all-ipv4.txt', 'w') as f:
    f.write('\n'.join(sorted(ipv4)))
with open('ipset-all-ipv6.txt', 'w') as f:
    f.write('\n'.join(sorted(ipv6)))
with open('ipset-all.txt', 'w') as f:
    f.write('\n'.join(sorted(ipv4 + ipv6)))