def format_fingerprint(fingerprint, sep=':'):
    'format a hex fingerprint as 00:11:22:33:44:55...'
    parts = [fingerprint[n*2:n*2+2] for n in range(len(fingerprint) // 2)]
    return sep.join(parts)

def format_size(size):
    return '{0:.2f} MB'.format(size/1024/1024)
