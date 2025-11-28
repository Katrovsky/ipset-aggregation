import socket
import ipaddress
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

TEST_URLS = [
    "https://cdn.cookielaw.org/scripttemplates/202501.2.0/otBannerSdk.js",
    "https://genshin.jmp.blue/characters/all",
    "https://api.frankfurter.dev/v1/2000-01-01..2002-12-31",
    "https://genderize.io/",
    "https://j.dejure.org/jcg/doctrine/doctrine_banner.webp",
    "https://tcp1620-01.dubybot.live/1MB.bin",
    "https://tcp1620-02.dubybot.live/1MB.bin",
    "https://tcp1620-05.dubybot.live/1MB.bin",
    "https://tcp1620-06.dubybot.live/1MB.bin",
    "https://eu.api.ovh.com/console/rapidoc-min.js",
    "https://ovh.sfx.ovh/10M.bin",
    "https://oracle.sfx.ovh/10M.bin",
    "https://tms.delta.com/delta/dl_anderson/Bootstrap.js",
    "https://corp.kaltura.com/wp-content/cache/min/1/wp-content/themes/airfleet/dist/styles/theme.css",
    "https://api.usercentrics.eu/gvl/v3/en.json",
    "https://openoffice.apache.org/images/blog/rejected.png",
    "https://www.juniper.net/etc.clientlibs/juniper/clientlibs/clientlib-site/resources/fonts/lato/Lato-Regular.woff2",
    "https://www.lg.com/lg5-common-gp/library/jquery.min.js",
    "https://media-assets.stryker.com/is/image/stryker/gateway_1920?$max_width_1410$",
    "https://cdn.eso.org/images/banner1920/eso2520a.jpg",
    "https://cloudlets.io/wp-content/themes/Avada/includes/lib/assets/fonts/fontawesome/webfonts/fa-solid-900.woff2",
    "https://renklisigorta.com.tr/teklif-al",
    "https://cdn.xuansiwei.com/common/lib/font-awesome/4.7.0/fontawesome-webfont.woff2"
]

def get_domain(url):
    return urlparse(url).netloc

def resolve_domain(domain):
    ips = set()
    try:
        result = socket.getaddrinfo(domain, None)
        for item in result:
            ips.add(item[4][0])
    except:
        pass
    return ips

def get_asn(ip):
    try:
        url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        asns = data.get('data', {}).get('asns', [])
        if asns:
            return asns[0].get('asn')
        return None
    except:
        return None

def get_subnet(ip, asn):
    try:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        prefixes = [p['prefix'] for p in data.get('data', {}).get('prefixes', [])]
        
        ip_obj = ipaddress.ip_address(ip)
        for prefix in prefixes:
            net = ipaddress.ip_network(prefix, strict=False)
            if ip_obj in net:
                return prefix
        return None
    except:
        return None

def aggregate_cidrs(ip_list):
    if not ip_list:
        return []
    networks = [ipaddress.ip_network(ip, strict=False) for ip in ip_list]
    collapsed = list(ipaddress.collapse_addresses(networks))
    return [str(net) for net in collapsed]

domains = set()
for url in TEST_URLS:
    domains.add(get_domain(url))

all_ips = set()
with ThreadPoolExecutor(max_workers=10) as executor:
    futures = {executor.submit(resolve_domain, domain): domain for domain in domains}
    for future in as_completed(futures):
        all_ips.update(future.result())

subnets = set()
for ip in all_ips:
    asn = get_asn(ip)
    if asn:
        subnet = get_subnet(ip, asn)
        if subnet:
            subnets.add(subnet)
        else:
            subnets.add(f"{ip}/{'128' if ':' in ip else '32'}")
    else:
        subnets.add(f"{ip}/{'128' if ':' in ip else '32'}")

ipv4 = [s for s in subnets if ':' not in s]
ipv6 = [s for s in subnets if ':' in s]

ipv4_aggregated = aggregate_cidrs(ipv4)
ipv6_aggregated = aggregate_cidrs(ipv6)

with open('ipset-all-ipv4.txt', 'w') as f:
    f.write('\n'.join(sorted(ipv4_aggregated, key=lambda x: ipaddress.ip_network(x))))

with open('ipset-all-ipv6.txt', 'w') as f:
    f.write('\n'.join(sorted(ipv6_aggregated, key=lambda x: ipaddress.ip_network(x))))

with open('ipset-all.txt', 'w') as f:
    all_sorted = sorted(ipv4_aggregated + ipv6_aggregated, 
                       key=lambda x: (1 if ':' in x else 0, ipaddress.ip_network(x)))
    f.write('\n'.join(all_sorted))
