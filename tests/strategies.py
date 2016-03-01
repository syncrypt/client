import hypothesis.strategies as st

__all__ = ('vault',)

MAX_FILES = 500

@st.composite
def file(draw, filename=st.lists(
        st.characters(blacklist_categories=('Cs', 'Cc'),
            blacklist_characters=('\0\n\r/\\')),
            min_size=1, average_size=20),
            content=st.binary(max_size=10000, average_size=100)):
    return {'filename': ''.join(draw(filename)),
            'content': draw(content)}

valid_file = file().filter(lambda f: not f['filename'] in ('.', '..'))

@st.composite
def vault(draw):
    # TODO: use st.recursive to generate files in folders
    # TODO: filter duplicate filenames
    return draw(st.lists(valid_file, average_size=5, max_size=MAX_FILES))

if __name__ == '__main__':
    print (vault().example())
    print (vault().example())
    print (vault().example())
