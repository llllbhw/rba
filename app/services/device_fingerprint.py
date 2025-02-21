import hashlib

def get_device_fingerprint(request):
    client_info = [
        request.user_agent.string,
        request.headers.get('Accept-Language'),
        request.headers.get('User-Agent'),
        str(request.remote_addr)
    ]
    fingerprint_str = ''.join(client_info)
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()