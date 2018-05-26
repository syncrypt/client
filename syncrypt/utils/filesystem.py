import os
import os.path


def folder_size(folder):
    total_size = os.path.getsize(folder)
    for item in os.listdir(folder):
        itempath = os.path.join(folder, item)
        if os.path.isfile(itempath):
            total_size += os.path.getsize(itempath)
        elif os.path.isdir(itempath):
            total_size += folder_size(itempath)
    return total_size


def splitpath(path, maxdepth=20, pathmod=os.path):
    (head, tail) = pathmod.split(path)
    return (
        splitpath(head, maxdepth - 1, pathmod=pathmod) + [tail]
        if maxdepth and head and head != path
        else [head or tail]
    )


def is_empty(folder):
    return not bool(os.listdir(folder))
