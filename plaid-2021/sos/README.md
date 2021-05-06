Secure OCaml Sandbox
---

Our objective in this challenge is to upload an arbitrary OCaml program that reads the flag from `/flag` and prints it to stdout.
That wouldn't be very interesting if it wasn't for the heavily restricted version of the standard library our program is sandboxed with:
```ocaml
open struct
  let blocked = `Blocked

  module Blocked = struct
    let blocked = blocked
  end
end

module Fixed_stdlib = struct
  let open_in = blocked
  let open_in_bin = blocked
  let open_in_gen = blocked
  (* ...~150 more similar lines... *)
end

include Fixed_stdlib
```

Pretty much everything even tangentially related to IO is mercilessly stripped away.
Unsafe functions, such as `Array.unsafe_get`, which could allow us to subvert the type system and execute arbitrary code, are also banned.

So, how do we escape the sandbox to read the flag?

Before we get to the final exploit, I want to briefly discuss a couple of unintended solutions,
and also our failed attempts at breaking out of the sandbox. If you're only interested in the solution out team came up with, you can jump directly to that.

Insecure OCaml Sandbox
---

The first unintended solution was discovered during the event by some of the teams. PPP published a fixed version promptly,
and the diff with the original version is mostly self-explanatory:
```diff
--- sos/src/main	2021-04-12 09:28:12.000000000 +0500
+++ src/main	2021-04-17 03:48:57.000000000 +0500
@@ -7,6 +7,6 @@
 	exit 1
 fi
 
-echo "open! Sos" > user/exploit.ml
+echo "open! Sos;;" > user/exploit.ml
 cat /input/exploit.ml >> user/exploit.ml
 dune exec user/exploit.exe
```

`open! Sos` is the line prepended to your program to make it use the sandboxed standard library.
Without the trailing `;;`, you could start the malicious program with something like `.Fixed_uchar`
to only import one of the submodules of the patched standard library instead of the whole deal.
The rest is trivial.

The second unintended (I believe) solution comes from [SECCON 2020 writeups](https://moraprogramming.hateblo.jp/entry/2020/10/14/185946), which apparently
had a challenge named `mlml` with an even stonger OCaml sandbox. Their reference solution uses the unsound implementation of pattern matching in
the OCaml compiler to achieve RCE. While extremely clever and cool, I doubt that PPP wanted us to essentially copy/paste an existing snippet of code
with minor modifications. Besides, there's little point in elaborately patching the stdlib if all you wanted to target was the compiler.
