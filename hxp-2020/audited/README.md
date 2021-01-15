In this challenge a Python program reads a fragment of Python code from standard input (technically, `audited.py` was running behind [ynetd](https://github.com/rwstauner/ynetd)), compiles it into a code object and executes it:

```python
code = compile(sys.stdin.read(), '<user input>', 'exec')
...
namespace = {}
exec(code, namespace, namespace)
```


Of course, you cannot simply execute arbitrary code and read a flag, the authors made `audited.py` look like some sort of a sandbox with a relatively recent feature [runtime audit hooks](https://www.python.org/dev/peps/pep-0578/).

The hook is quite straighforward:
```python
from os import _exit as __exit

def audit(name, args):
    if not audit.did_exec and name == 'exec':
        audit.did_exec = True
    else:
        __exit(1)
audit.did_exec = False
```

It basically allows `exec` to be executed only once (the invokation that executes compiled code from the input) and calls `__exit(1)` (`os._exit` imported as `__exit`) after any subsequent audit event.

