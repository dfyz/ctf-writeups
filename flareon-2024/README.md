When solving the last challenge of [Flare-On 11](https://cloud.google.com/blog/topics/threat-intelligence/announcing-eleventh-annual-flare-on-challenge), I decided on a whim to see if current-generation LLMs are of any help in CTF-style reverse engineering.

The answer is "definitely yes, but with caveats" (more specifically, I was using Claude 3.5 Sonnet, but I suppose the answer is the same for GPT-4/Gemini/...). You obviously can't drop the binary directly into the LLM and get the flag out (yet?), but you definitely can automate the bulk of reverse engineering.

The challenge is a UEFI firmware image, but as far as I can see, there's really nothing UEFI-specific to it (which is honestly a shame because I really wanted to use this challenge as an excuse to re-read [this excellent book](https://nostarch.com/rootkits)).
The only program you need to reverse is the custom modification of the shell built into [EDK2](https://github.com/tianocore/edk2), and for all intents and purposes it's just a regular PE file which you can analyze statically (with Binary Ninja) or dynamically (with qemu and gdb).
In fact, the PE is also mostly irrelevant, since the core of the challenge is to find the correct input for three different programs for a custom virtual machine. The only part of the binary we need is the interpreter for the VM and the programs themselves.

First, I copied and pasted the Binary Ninja HLIL for the VM interpreter into the LLM and asked for a disassembler for the VM bytecode.

![disasm](https://github.com/user-attachments/assets/5308c43c-2e5d-4b9d-a7fb-fa3b2f44bf81)

Then I dumped the first bytecode program from gdb memory and disassembled it with the LLM-generated code.

![gdb](https://github.com/user-attachments/assets/be86d7d8-c425-485e-9cd3-08caed6943d9)

After disassembling, I asked the LLM to "decompile" it. It generated a Python script, from which it was obvious that the input is just compared against a hardcoded character sequence. I modified the script to print the sequence and got `DaCubicleLife101`, which was accepted as a valid input.

![stage1](https://github.com/user-attachments/assets/a6034d91-9558-4b58-a460-62871f48fbfc)

Excited, I repeated the same for the second bytecode program. Here, it was obvious that the input can be bruteforced character-by-character, so I manually added 10 Python lines to do this, and got `G3tDaJ0bD0neM4te`, which was also accepted.

![stage2](https://github.com/user-attachments/assets/cd44122b-5f8b-4736-8acb-aa2e486de9aa)

The last program was where the troubles started. The decompilation was fine, but I couldn't see an obvious way to guess the correct input.

![stage3](https://github.com/user-attachments/assets/ab90d13a-e5a6-4904-9c8c-afec951c7bc6)

I asked the LLM to write a Z3 solver, which it did.

![stage3_z3](https://github.com/user-attachments/assets/9a556194-a875-4576-91ef-32825ec415e0)

However, it reported that no solutions were found. The human-in-the-loop (me) was too tired/stupid to see what the problem was, so he spent a lot of time basically imploring LLM to try harder, but none of the solver modifications worked. However, in one of the attempts the 
LLM noticed that the first half of the input is bruteforceable after all. I modified the bruteforce part slightly to avoid doing some redundant work, and came up with a plausible first half: `VerYDumB`.

![stage3_bruteforce](https://github.com/user-attachments/assets/bc6bcd3f-4cb6-479d-bb11-d40b98726184)

It didn't really help, even though the LLM claimed it would.

![stage3_fail](https://github.com/user-attachments/assets/da71fcc1-976f-4795-ac37-360d103846bb)

At this point, I decided to cheese it and try to guess the last word. The first attempt failed.

![stage3_checksum](https://github.com/user-attachments/assets/08ac6077-0313-4d05-9b28-0c51b93fed26)

However, a more comprehensive guesser instantly found the right second half: `password`. Which turned out to be correct.

![stage3_more_bruteforce](https://github.com/user-attachments/assets/92054f6e-a3ef-41b8-8f61-cfd4ca81a083)

And here's is the almost successfull LLM attempt to reconstruct the final flag (it didn't recognize the leetspeak in the last image).

![final_flag](https://github.com/user-attachments/assets/c48eb8d5-5e7e-4cb8-ad91-4f7368eb0c06)
