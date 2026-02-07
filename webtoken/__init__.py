import os, sys, importlib.util


module_name = 'webtoken'
file_path = f'{__file__.rsplit('/', 1)[0]}/{module_name}.py'
spec = importlib.util.spec_from_file_location(module_name, file_path)

if spec and spec.loader:
    lib = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = lib
    spec.loader.exec_module(lib)
    # sys.modules[__name__] = mod
else:
    print(f"Could not find or load {file_path}")


'''
Any import statement like 'import poo' in other files will still load poo.so by default. 
So - 'import module_name' or expose contents from the __init__.py like:
from .module_name import * 
'''