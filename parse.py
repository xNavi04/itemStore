from urllib.parse import urlencode, urljoin, urlparse, parse_qs, urlunparse

def add_or_update_param(url, param_name, param_value):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    params[param_name] = [param_value]
    new_query = urlencode(params, doseq=True)
    new_url = urljoin(url, '?' + new_query)
    return new_url

def remove_last_param(url):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    if params:
        last_key = list(params.keys())[-1]
        params.pop(last_key, None)
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse(
            (parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment)
        )
        return new_url
    else:
        return url

def check_filter(url):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    return params