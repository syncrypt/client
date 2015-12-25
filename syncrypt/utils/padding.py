class PKCS5Padding(object):
    @staticmethod
    def pad(s, block_size):
        if len(s) % block_size > 0:
            return s + str.encode((block_size - len(s) % block_size) *
                    chr(block_size - len(s) % block_size))
        else:
            return s

    @staticmethod
    def unpad(s):
        num_pad_chars = s[-1]
        if s[-num_pad_chars:] == s[-1:] * num_pad_chars:
            return s[:-num_pad_chars]
        else:
            return s




