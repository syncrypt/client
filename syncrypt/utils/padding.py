class PKCS5Padding(object):
    @staticmethod
    def pad(s, block_size):
        padding = block_size - len(s) % block_size
        return s + bytes((padding,) * padding)

    @staticmethod
    def unpad(s):
        if len(s) == 0:
            return s
        num_pad_chars = s[-1]
        if s[-num_pad_chars:] == s[-1:] * num_pad_chars:
            return s[:-num_pad_chars]
        else:
            return s

