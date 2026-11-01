"""Shared API configuration validation. No networking or optional dependencies."""
import ipaddress
import re


def is_loopback_host(host):
    if host == 'localhost':
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except (ValueError, TypeError):
        return False


def validate_host(host):
    if host == 'localhost':
        return host
    try:
        if '%' in host:
            raise ValueError
        ipaddress.ip_address(host)
    except (ValueError, TypeError):
        raise ValueError('Bind host must be an IP literal or localhost') from None
    return host


def positive_int(value):
    if isinstance(value, bool) or not re.fullmatch(r'[0-9]+', str(value)) or int(value) <= 0:
        raise ValueError('Expected a positive integer')
    return int(value)


def boolean_env(value):
    if value not in ('0', '1'):
        raise ValueError('HEXSTRIKE_ALLOW_UNAUTHENTICATED_LOCAL must be 0 or 1')
    return value == '1'


def validate_token(token):
    if token and not re.fullmatch(r'[A-Za-z0-9._~+/-]{32,512}={0,2}', token):
        raise ValueError('HEXSTRIKE_API_TOKEN must be 32-514 ASCII bearer-token characters; use secrets.token_urlsafe(32)')
    return token


def validate_config(host, port, token, allow_local, debug=False, require_credentials=True):
    validate_host(host)
    if positive_int(port) > 65535:
        raise ValueError('Port must be between 1 and 65535')
    validate_token(token)
    if allow_local and not is_loopback_host(host):
        raise ValueError('Unauthenticated local mode requires a loopback bind')
    if debug and not is_loopback_host(host):
        raise ValueError('Debug mode requires a loopback bind')
    if require_credentials and not token and not allow_local:
        raise ValueError('Set HEXSTRIKE_API_TOKEN or explicitly opt into HEXSTRIKE_ALLOW_UNAUTHENTICATED_LOCAL=1')
