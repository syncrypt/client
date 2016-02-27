import hypothesis.strategies as st

__all__ = ('vault',)

#vault_files = \
#        st.recursive(st.floats() | st.booleans() | st.text() | st.none(),
#        lambda children: st.lists(children) | st.dictionaries(st.text(), children))

@st.composite
def file(draw, filename=st.text(min_size=1), size=st.integers(0,10000),
        content=st.binary()):
    return {'filename': draw(filename),
            'size': draw(size),
            'content': draw(content)}

@st.composite
def vault(draw, files=st.integers(0,1000)):
    # TODO: use st.recursive to generate files in folders
    return draw(st.lists(file(), min_size=1))

if __name__ == '__main__':
    print (vault().example())
    print (vault().example())
    print (vault().example())
