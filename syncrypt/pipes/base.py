#
#
#   FileReaderPipe(bundle)
#   >> DeflatingPipe('snappy')
#   >> PaddingPipe(16)
#   >> EncryptingPipe(bundle)
#   >> BufferingPipe(buf_size)
#
#

class BasePipe(object):



    def read(self, n=-1):
        pass
