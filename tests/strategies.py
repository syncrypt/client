import hypothesis.strategies as st

__all__ = ('files', 'file')

MAX_FILES = 500

@st.composite
def file(draw, filename=st.lists(
        st.characters(blacklist_categories=('Cc',),
            blacklist_characters=('\0\n\r/\\|><')),
            min_size=1, average_size=20, max_size=80),
            content=st.binary(max_size=10000, average_size=100)):
    return {'filename': ''.join(draw(filename)),
            'content': draw(content)}

valid_file = file()\
        .filter(lambda f: not f['filename'] in ('.', '..'))\
        .filter(lambda f: not f['filename'].startswith('.')) # exclude dotfiles for now

def has_no_duplicate(v):
    return len(v) == len({f['filename'] for f in v})

@st.composite
def files(draw):
    # TODO: use st.recursive to generate files in folders
    return draw(st.lists(valid_file, average_size=5, max_size=MAX_FILES)\
            .filter(has_no_duplicate))

#valid_vault = vault().filter(has_no_duplicate)

if __name__ == '__main__':
    print (files().example())
    print (files().example())
    print (files().example())
