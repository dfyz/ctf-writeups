## Description

In this challenge a Python program reads a fragment of Python code from standard input (technically, `audited.py` was running behind [ynetd](https://github.com/rwstauner/ynetd)), compiles it into a code object and executes it:

```python
code = compile(sys.stdin.read(), '<user input>', 'exec')
...
namespace = {}
exec(code, namespace, namespace)
```


Of course, you cannot simply execute arbitrary code and read the flag, the authors made `audited.py` look like some sort of a sandbox with a relatively recent feature [runtime audit hooks](https://www.python.org/dev/peps/pep-0578/). TLDR: all things from [this table](https://docs.python.org/3/library/audit_events.html) raise an audit event which is processed by a callable registered with `sys.addaudithook`.

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


## Path to the Solution

Naturally, the first idea was to through [the table of audit events](https://docs.python.org/3/library/audit_events.html) and find something that wouldn't cause an audit event but allow to read the flag. This attempt was futile, nothing particularly interesting is missing in the table.

One of the next ideas was about trying to execute some code after the audit mechanism is de-initialised. For instance, define a class with a finalizer:

```python
class C:

    def __del__(self):
        print("hi there")
```

`__del__` is supposed to be called when an object is garbage collected (OK, to be more precise, it's not guaranteed, but it usually happens), which in theory might happen after the audit mechanism is de-initialised.

We carefully examined [pylifecycle.c](https://github.com/python/cpython/blob/master/Python/pylifecycle.c) but `_PySys_ClearAuditHooks` was one of the last things in finalising the interpreter state. Surprisingly, later we found [this issue](https://bugs.python.org/issue41162) - "Clear audit hooks after destructors". It was indeed the case that destructors were called before `_PySys_ClearAuditHooks` in the previous versions of Python, and what I think is really cool, [this bug was reported by the organizers of 0CTF/TCTF 2020 Quals](https://ctftime.org/writeup/21982) after this trick was discovered as an interesting unintended solution of a similar challenge.


## Solution

OK, after looking at the audit mechanism itself we took a break and assumed that it's pretty solid and realized that it might haven been better for us to attack the logic of the hook function.