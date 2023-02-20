### Intro

[Sice Supervisor](https://github.com/dicegang/dicectf-2023-challenges/tree/main/pwn/sice-supervisor) was a pretty cool heap memory corruption challenge from DiceCTF 2023 that no team solved during the CTF. We ([More Smoked Leet Chicken](https://ctftime.org/team/1005/)) came pretty close to getting the flag, though, so I thought I'd try writing it up.

Heads-up: a typical heap exploitation writeup assumes you memorized a myriad of little tricks before reading, and goes like this:
> The MD5 of the given `libc.so` is `76b4e83...`. It is very well known that this library is vulnerable to House of Serendipity *a link to an obscure Taiwanese blog* and has exactly 12 gadgets we can exploit. By enumerating them all...

I tried to avoid this style as much as possible. To understand this writeup, you only need to:
  * be comfortable with reading both C and Rust code
  * be familiar with basics of multi-threaded programming: e.g., know what a thread is, how to spawn one, and how to wait for its completion

### Exploration

Sice Supervisor is a tandem of two programs (thankfully, we are given the source code for both): the **daemon** (written in C) and the **supervisor** (written in Rust). The daemon is a ~~contrived~~ simple in-memory database with a CLI interface capable of adding, removing, editing and inspecting chunks of data. The supervisor's job is to spawn a daemon instance, receive commands from the user (that would be us), send them to the daemon instance, and then transfer the daemon output back to the user after some postprocessing.

As neither supervisor nor daemon interacts with the file system at all, the only way to read the flag from the local filesystem is to hunt for some sort of memory safety issue to achieve remote command execution. The Rust supervisor with no `unsafe` blocks is more likely (although not [guaranteed](https://brycec.me/posts/dicectf_2023_challenges#chessrs)) to be memory-safe, so let's focus on the C daemon instead.

Let's try to work backwards and see which memory region we can stomp over (with a hypothetical memory safety issue) to gain execution control. The daemon itself is tiny and there's not a lot to corrupt, however we do have [glibc](https://www.gnu.org/software/libc/) mapped into our address space. A quickly analysis of the glibc binary with a [disassembler](https://binary.ninja/) of our choice reveals that there are all sorts of overwritable function pointers. Of those, [\_\_free_hook()](https://www.gnu.org/software/libc/manual/html_node/Hooks-for-Malloc.html) appears to be the [best target]((https://developers.redhat.com/articles/2021/08/25/securing-malloc-glibc-why-malloc-hooks-had-go)): we can ask the daemon to delete any data chunk, which results in `__free_hook()` being called. We also control the data being `free()`'ed, so if we somehow sneak, say, [system()](https://man7.org/linux/man-pages/man3/system.3.html) into the hook, then it's instant game over.

So, perhaps we can find some sort of buffer overflow in the daemon implementation that can reach `__free_hook()`?

Unfortunately, the code is surprisingly decent for a C program: no integer overflows, no double-frees or dangling pointers, and all array indices are checked against array sizes. There's one thing that seems obviously fishy, though: even though the daemon processes the commands sequentially without using mutexes, each command is actually processed in a new thread. That would be just bad programming rather than an exploitable bug, if it wasn't for this:
```c
pthread_t tid;
pthread_create(&tid, ...);
pthread_detach(tid);
sleep(3);
```

In other words, instead of properly waiting for the thread to terminate (with [pthread_join()](https://man7.org/linux/man-pages/man3/pthread_join.3.html)) before starting a new command, we just assume it terminates in no more than 3 seconds.

### An wild race condition appears

🚩🚩🚩NEVER EVER DO THIS IN REAL LIFE🚩🚩🚩

Best case, a thread *accidentally* needs more than 3 seconds to finish its job for whatever reason, and a new thread is spawned while the old one is still alive. This means there are now two threads operating on the same data without mutexes, and you get a lot of fun staring at mysterious core dumps. Worst case, a motivated attacker finds a way to *intentionally* stall a thread for more than 3 seconds and then cleverly exploit the resulting race condition to overwrite some data they weren't supposed to.

Wait, we *are* the motivated attacker. Let's do exactly this.

This is actually harder than it sounds: all functions in the C daemon are straightforward, and have time complexity of either `O(1)` or `O(N)` (where `N` is the size of the data chunk in bytes). To make them take longer than 3 seconds, we need to allocate *huge* data chunks and risk running out of memory when running our exploit. Yet, when we look at the function editing data in the C daemon, we see there is a better way:
```c
void * edit_deet(void * args) {
  unsigned long i = (unsigned long) ((void **) args)[0];
  ...
    unsigned long sz = sizes[i];
    printf("Editing deet of size %lu\n", sz);
    // `deets[i]` is the target data chunk, `args[1]` is the source data we control
    memcpy(deets[i], ((void **) args)[1], sz);
```

If we find a way to block `printf()` for a long time and re-allocate `deets[i]` with a smaller size in the meanwhile, then we have a perfect buffer overflow: the `memcpy()` call will write arbitrary data we control past the bytes allocated for `deets[i]`.

But how do we slow down `printf()`?

### Interlude #1: Linux pipes and buffering

The supervisor redirects the stdout of the daemon to a [pipe](https://man7.org/linux/man-pages/man7/pipe.7.html) and spawns a new thread that repeatedly reads from this pipe in a busy loop. The man page says:

> A pipe has a limited capacity.  If the pipe is full, then a write(2) will block [...]
>
> [...] the pipe capacity is 16 pages (i.e., 65,536 bytes in a system with a page size of 4096 bytes).

This suggests that if we write 65K bytes to stdout and the supervisor fails to read them in time, the next write will block. Indeed, when we run a pair of test programs ([Rust parent](ctf-writeups/tree/master/dice-2023/sice/parent.rs), [C child](ctf-writeups/tree/master/dice-2023/sice/child.rs)) under [strace](https://strace.io/), we get the following output:
```
7992  19:55:21 clock_nanosleep(CLOCK_REALTIME, 0, {tv_sec=10, tv_nsec=0},  <unfinished ...>
...
7993  19:55:22 write(1, "A", 1)         = 1
7993  19:55:22 write(1, "A", 1 <unfinished ...>
7992  19:55:31 <... clock_nanosleep resumed>0x7ffcf43c0e10) = 0
7992  19:55:31 read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 100000) = 65536
7993  19:55:31 <... write resumed>)     = 1
7992  19:55:31 wait4(7993,  <unfinished ...>
7993  19:55:31 write(1, "A", 1)         = 1
7993  19:55:31 write(1, "A", 1)         = 1
...
7992  19:55:31 <... wait4 resumed>[{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 7993
```

The child process (`7993`) was stuck in the `write()` syscall for 9 seconds because the pipe got clogged. Then the parent (`7992`) woke up, read exactly 65K bytes from the pipe buffer, and allowed the child to proceed.

### Interlude #2: Rust `regex` CVE

Writing 65K bytes to the stdout pipe from the daemon is trivial: all we need to do is create a large chunk of data and make the daemon print it. But we also need to prevent the supervisor from draining the pipe, at least temporarily. We control the regular expression that the supervisor uses to filter the output from the daemon, so it's natural to try to trigger some sort of [ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS), so that the supervisor thread wastes CPU cycles matching the regexp instead of polling for stdout data.

The `regex` crate by burntsushi@ is explicitly [designed](https://docs.rs/regex/latest/regex/#untrusted-input) to "handle both untrusted regular expressions and untrusted search text", which is bad news for us. The good news is that the challenge setup "accidentally" uses an older version of `regex` with a known [CVE](https://github.com/rust-lang/regex/commit/ae70b41d4f46641dbc45c7a4f87954aea356283e).

This essentially means we can pause the supervisor for a controlled amount of time by providing a regular expression with a repeating empty sub-group (e.g, `(?:){N}`, where `N` is a huge number).

### Corrupting the heap

So, if we re-compile the daemon with [asan](https://github.com/google/sanitizers/wiki/AddressSanitizer), feed the evil regexp to the supervisor, clog the stdout pipe, and then re-allocate the data chunk with a smaller size just before `memcpy(...)`, we indeed get a very promising crash:
```
==99404==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x626000002810 at pc 0x7f8727849d21 bp 0x7f87248fce20 sp 0x7f87248fc5d0
WRITE of size 100000 at 0x626000002810 thread T7
    #0 0x7f8727849d20 in __interceptor_memcpy (/lib64/libasan.so.8+0x49d20)
    #1 0x401954 in edit_deet deet.c:62
    #2 0x7f87276ae12c in start_thread (/lib64/libc.so.6+0x8b12c)
    #3 0x7f872772fbbf in __clone3 (/lib64/libc.so.6+0x10cbbf)
```

Sadly, we still have a long way to go to remote code execution. Data chunks are allocated on the heap, and being able to write past the chunk bounds is not enough. To see why, we need to dig into the [internals](https://sourceware.org/glibc/wiki/MallocInternals) of the heap allocator used in glibc and read its source code (the challenge is deployed on Ubuntu 18.04, so we need version [2.27](https://sourceware.org/git/?p=glibc.git;a=commit;h=23158b08a0908f381459f273a984c6fd328363cb)).

Poking into the daemon binary with `gdb` and cross-referencing the results against the source code, we can determine that the memory layout looks like this:

**???**

Our data chunks are created from auxiliary threads, so they get placed in a [heap](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/arena.c;h=37183cfb6ab5d0735cc82759626670aff3832cd0;hb=23158b08a0908f381459f273a984c6fd328363cb#l452) that is allocated with `mmap()`. glibc is also allocated with `mmap`, so the heap and `__free_hook` are thankfully not too far from each other. However:
  * Due to the way the challenge is setup, we can only overflow up to 100K bytes, but the difference between the heap and `__free_hook` is much larger than 100K bytes.
  * Even if we could reach `__free_hook` with the overflow, the space *between* the heap and glibc is not readable/writable, so if we try to stomp over it, we die.
  * `mmap()`'ed addresses are randomized with [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization), we don't know the address of `system()`, which we want to put into `__free_hook`.
  * All `mmap()`'ed addresses share the same ASLR base, so you'd think that the *difference* between the heap and `__free_hook` is known and constant. However, glibc [aligns](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/arena.c;h=37183cfb6ab5d0735cc82759626670aff3832cd0;hb=23158b08a0908f381459f273a984c6fd328363cb#l494) the `mmap()`'ed heap to 64 megabytes by `munmap()`'ing some of the initial heap bytes. So the difference also varies slightly from run to run.

Let's first pretend there's no ASLR and try to reach `__free_hook` anyway. The heap has a dummy chunk with free bytes of the heap at the very end, and the size of this chunk is stored inline. With our overflow, we can overwrite the size to whatever value we want. This will trick glibc into thinking that our heap has more free bytes at the end.

What if we set the size of the dummy chunk to a very large value? Then we can allocate a fake chunk that will span the difference between the heap and glibc (we don't write anything into it, so it's OK) and another chunk right before `__free_hook`:

**???**

We can then edit the chunk before `__free_hook` and set it to `system()`. This would actually work, if it wasn't for the fact that glibc expects to find heap metadata for a chunk by [zeroing](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/arena.c;h=37183cfb6ab5d0735cc82759626670aff3832cd0;hb=23158b08a0908f381459f273a984c6fd328363cb#l128) its last 3 bytes. In the picture, `__free_hook` has address `0x7f7c3cded8e8`, but there's no valid heap metadata at `0x7f7c3c000000` (we only have one at `0x7f7c38000000`), so we segfault.

Okay! After reading more source code we find out that there are no limits on the size of the chunk we allocate. Let's allocate a chunk so large it wraps around in 64-bit address space (setting the size of the dummy chunk to `MAX_INT` before that) and lands *inside* heap metadata. The difference between the dummy chunk and the heap metadata is constant, so we don't even need an ASLR bypass. This way, we get an ability to corrupt heap metadata:

**???**

It is not hard to see what metadata we should corrupt: the heap metadata has pointers to linked lists of free chunks that are can be used to serve allocations. The layout of metadata looks roughly like this:

**???**

`bins` is a doubly-linked list of chunks, `fastbinsY` is a singly-linked one. If we place a fake chunk that points to `__free_hook` on either, we win. Which one to choose?

### Interlude: defeating ASLR

In addition to corrupting heap metadata, we can also read from it. Here, we get lucky: `metadata->next` points to [main_arena](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=23158b08a0908f381459f273a984c6fd328363cb#l1761), which is located somewhere inside glibc and is used to serve allocations for the main thread. All addresses inside glibc (e.g., `system()`) are located at fixed offset from each other, so if we know the address of `main_arena`, we can compute any address in glibc and bypass ASLR.

### Back to pwning

It turns out that `bins` is a worse target: since it's a doubly-linked list, it has an [additional protection](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=23158b08a0908f381459f273a984c6fd328363cb#l1409) that requires the fake chunk to have a valid `back` pointer.

But even we target `fastbinsY` (which is singly-linked) instead, we face another [protection](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=23158b08a0908f381459f273a984c6fd328363cb#l3596). Fastbins only serve chunks of fixed small sizes (from 0x20 to 0x80), and glibc requires the fake chunk to have a size that can be put into a fastbin.

[This](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=23158b08a0908f381459f273a984c6fd328363cb#l1591) is the function used to convert the chunk size into the fastbin index. Essentially, this means we need to arrange a fake chunk like this in memory:

**???**

Here, `??` should be an arbitrary number from `20` to `80`. Here we get lucky once again: there are locks for standard streams just before `__free_hook`. When they are locked, their `owner` [field](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/nptl/libc-lock.h;h=801bcf7913a3ea7a0c7bd3ba529164902e8974c9;hb=23158b08a0908f381459f273a984c6fd328363cb#l32) is set to an address somewhere in libc, which looks like `0x00007f...`. Since `0x7f` is a valid fastbin chunk size, we can form a fake chunk around the `owner` like this:

**???**

How do we ensure that stdout locked when we are allocating the fake chunk, though?  We can just use the same race condition again to make `printf()` block for a long time. And `printf()` holds the stdout lock.

Combining everything into a big hairy [exploit](ctf-writeups/tree/master/dice-2023/sice/solve.py), we run it against the remote server and finally get the flag:

**???**