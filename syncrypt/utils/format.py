from math import log

def format_fingerprint(fingerprint, sep=':'):
    'format a hex fingerprint as 00:11:22:33:44:55...'
    parts = [fingerprint[n*2:n*2+2] for n in range(len(fingerprint) // 2)]
    return sep.join(parts)

SIZE_UNITS = [('bytes', 0), ('kB', 0), ('MB', 2), ('GB', 2), ('TB', 2), ('PB', 2)]

def format_size(size):
    if size is None:
        return None
    if size == 0:
        return '0 bytes'
    if size == 1:
        return '1 byte'
    if size > 1:
        exponent = min(int(log(size, 1024)), len(SIZE_UNITS) - 1)
        quotient = float(size) / 1024**exponent
        unit, num_decimals = SIZE_UNITS[exponent]
        format_string = '{:.%sf} {}' % (num_decimals)
        return format_string.format(quotient, unit)

def size_with_unit(size):
    if size is None:
        return None
    if size == 0:
        return (0, 'bytes')
    if size == 1:
        return (1, 'byte')

    size_formatted, size_unit = format_size(size).split(" ")
    exponent = min(int(log(size, 1024)), len(SIZE_UNITS) - 1)
    quotient = float(size) / 1024**exponent
    unit, num_decimals = SIZE_UNITS[exponent]
    if num_decimals > 0:
        return (float(size_formatted), unit)
    else:
        return (int(size_formatted), unit)
