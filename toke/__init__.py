import os, sys, importlib.util


module_name = 'toke'
file_path = f'{__file__.rsplit('/', 1)[0]}/toke.py'
spec = importlib.util.spec_from_file_location(module_name, file_path)

if spec and spec.loader:
    toke = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = toke
    spec.loader.exec_module(toke)
    # sys.modules[__name__] = mod
else:
    print(f"Could not find or load {file_path}")

# Note: Any import statement like 'import poo' in other files will still load poo.so by default. 
# They would need to use 'import module_name' or you would need to expose its contents
# from the __init__.py like:
# from .module_name import * 