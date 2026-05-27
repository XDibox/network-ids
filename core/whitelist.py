import ipaddress
from config import WHITELIST, WHITELIST_NETWORKS

_networks = [ipaddress.ip_network(n, strict=False) for n in WHITELIST_NETWORKS]


def is_whitelisted(ip: str) -> bool:
    if ip in WHITELIST:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _networks)
    except ValueError:
        return False
