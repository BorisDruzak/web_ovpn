"""Validate the protected final resolver policy without accepting hostnames/code."""
import ipaddress


def validate(value):
    if not isinstance(value,list) or not 1<=len(value)<=4:raise ValueError('Invalid final DNS policy')
    result=[]
    for item in value:
        if not isinstance(item,str) or '%' in item:raise ValueError('Invalid final DNS policy')
        address=ipaddress.ip_address(item)
        if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
            raise ValueError('Invalid final DNS policy')
        text=str(address)
        if text in result:raise ValueError('Invalid final DNS policy')
        result.append(text)
    return {'servers':result}
