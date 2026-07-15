# Introduction

This is my writeup of solving lowfunheap CTF Challenge.

# Challenge Description

From ctftime: I'm sure you'll have your pleasure with this nice windows task. Thankfully on windows there are high quality software analysing tools aiming to make your day brighter.

This CTF Challenge focuses on exploiting Windows' NT Heap Low Fragmentation Heap. Originally from the Hack.lu CTF 2020. Unlike most heap challenges, this one requires knowledge of Windows Internals.

## Difficulty

High

# Resources

[Challenge](https://ctftime.org/task/13503)

[Official Challenge Site](https://archive.fluxfingers.net/2020/challenges/13.html)

https://github.com/leesh3288/CTF/tree/master/2020/Hacklu_2020/LowFunHeap

[Windows 10 ISO](https://archive.org/details/win-10-2004-english-x-64_20250829)

[Low Fragmentation Heap](https://learn.microsoft.com/en-us/windows/win32/memory/low-fragmentation-heap)

[Black hat write up about LFH](https://www.illmatics.com/Understanding_the_LFH.pdf)

https://github.com/saaramar/Deterministic_LFH

[Windows 8 Internals](https://media.blackhat.com/bh-us-12/Briefings/Valasek/BH_US_12_Valasek_Windows_8_Heap_Internals_Slides.pdf)

[Windows 10 Segment Heap](https://blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals.pdf)

## Looking for something else

Here's a list of "awesome windows ctfs"
https://zaratec.io/awesome-windows-ctf/

# Walkthrough

1. Download/Create Windows VM

This challenge was designed for Windows 10 Pro 2004 (updated to October 2020). Use the link above to download the iso for this version. Download the ISO and create a vm to run the challenge.

2. Static Analysis
Let's start with a static analysis to get an idea of what lfh.exe is doing. Let's pop this open in Ghidra and have a looksee. What am I looking for here?
* Strings
	* "C:\flag.txt "
* Functions for user input
	* recv
* Network connectivity - is it a network application?
	* I found network functions that bind to port 9999 on 0.0.0.0 - yes this is a network application.
Application is waiting for a Command byte of '1' or '3'
Since I already know this is targeting the heap, i'm going to assert the command '1' is used for our grooming, and '3' will be the vuln

## Command 1 Behavior

Triggered when a client sends a message that begins with '1'
![[Pasted image 20260506204037.png]]
This section of code received 1 character from the socket, stores the result in a char variable (uVar1) and then tests to see if it is '1'.

- Later on, we can see that the server is expecting a string immediately following the '1':
![[Pasted image 20260506204415.png]]
After receiving the command byte `'1'`, the server expects additional client-controlled string data.
There are no limits on the length as is described in the Heap Allocations section below
## Heap Allocations
There are two heap allocations every time Command 1 is called. The first allocation is a heap allocation of 32 bytes. This is used to store an object of "OneObject". The details are described in the Allocated Objects section below.

The second allocation is used to store the string that was sent by the client. The function "recvToBuff" creates a temporary buffer and receives one byte at a time until '\n' is received.
![[Pasted image 20260506210011.png|480]]
If the data received is larger than the temporary buffer, the function increases the size of the temporary buffer and continues reading data one byte at a time. The exact method of reallocation has not been fully analyzed.

Once the '\n' is received, the function allocates a new buffer large enough to hold the entire string plus a '\0' byte and then copies the temporary buffer to the newly allocated string. Because the client fully controls the input length, the attacker can influence the size class of the resulting heap allocation.
![[Pasted image 20260506210335.png]]
Finally, the buffer holding the client's string is stored as the last element of the OneObject that was previously created.
![[Pasted image 20260506210513.png]]


## Allocated Object
Command 1 allocates this struct:
```
struct OneObject{
	/* 0x00 */ int ptr_vtable;
	/* 0x04 */ char unknown[24];
	/* 0x1c */ char *buffer;
}
```
## Global state

This function uses a global index table variable that behaves like a ring buffer. After 256 insertions the index wraps. Object replacement behavior has not yet been fully analyzed. The global index table is statically allocated with a length of 256.
![[Pasted image 20260506205508.png]]
![[Pasted image 20260506205614.png]]
The dynamically allocated string buffer remains referenced by the OneObject object through the global index table.

The exact use of this ring buffer was not fully understood during this exercise. This warrants further investigation
# Command 3 Behavior
- allocate 8 byte object (ThreeObj)
- 
```
struct ThreeObj {
	/* 0x00 */ fourObj *array;
	/* 0x04 */ INT arrayLen;
}

struct fourObj {
	/* 0x00 */ char *field0;
	/* 0x04 */ int unk4;
	/* 0x08 */ int unk8;
	/* 0x0c */ char *fieldC;
} fourObj;
```

| Object         | Allocated by      | Freed By     | Referenced By |
| -------------- | ----------------- | ------------ | ------------- |
| oneObj         | command '1'       | command '3' (see below) | aPtrIndex     |
| fourObj.field0 | recvToBuff (safe) | cleanup Loop | fourObj       |
| fourObj.fieldC | recvToBuff (safe) | cleanup loop | fourObj       |
- take 18 allocations to activate LFH
- so we need at least 18 allocations of 0x20
- then we should see the LFH active in Windbg

Turns out that "Freed By" question mark from before has an easy answer: every time the server sees a '3' byte, before it even looks at the new batch you're sending, it unconditionally frees everything from the *previous* '3' batch. So sending a '3' with a bogus element count (0xffff works nicely, it always fails validation) is a free way to say "free everything, allocate nothing." Handy.

## Finding the bugs

**Bug #1 lives in Command 1.** Remember `recvToBuff`, the helper that reads a line and allocates a buffer for it? I sent it a completely empty line — just `\n`, no data — and noticed the buffer-allocation step gets skipped entirely if the line is empty. So `OneObject.buffer` never gets written. It just sits there holding whatever garbage was already in that heap chunk. And since we just recycled a bunch of 0x20-byte chunks with our LFH-activation spray, that garbage is often *our own* leftover data.

Even better: if that garbage happens to look like a non-null pointer, the server treats it as one — it does a `strlen()` and sends back whatever's at that address. That's an arbitrary-read primitive, not just an echo of old bytes. I don't end up exercising this leak for the exploit -- more on that later.

**Bug #2 lives in Command 3**, and it's the one that actually gets us code execution. The per-element index you send is only checked against the *upper* bound (`index < elem_cnt`). Nobody checks that it's not negative. Since indexing is just pointer math (`array_base + index * 0x10`), a negative index walks backward past the start of the array — into whatever heap chunk happens to be sitting right before it.

## From OOB write to code execution

So now I've got a write primitive that can land *before* my `fourObj` array. What's actually sitting there? If I've groomed things right, it's a live `OneObject` — and the very first field of `OneObject` is its vtable pointer.

The plan; overwrite the vtable pointer with a pointer to a fake table I control, and get the server to call through it.

Turns out the server does exactly that. After any Command 3 batch, it scans every element you just sent — if *any* of them has an empty or NULL `field0`/`fieldC`, it walks its whole list of live objects and calls three functions out of each one's vtable.

So one Command 3 call, two elements, does everything:
- **Element 0** (a normal, in-bounds write): I stash my ROP chain here, and give it an empty `fieldC` so this same call also fires the trigger above.
- **Element -5** (the OOB write): I stash an 8-byte fake vtable here. If this index lines up with a live `OneObject`, its vtable pointer gets replaced with a pointer to my fake table.

Why `-5` specifically, and not `-1` or `-3`? Short version: the heap secretly pads every chunk with an 8-byte header we don't see in our own struct, so `-5` is the smallest index that lands on an actual chunk boundary instead of the middle of one.

The other detail (only visible in the raw disassembly, not the decompiled pseudocode): right before the server calls through the hijacked vtable, it happens to load a CPU register (EBP) from that same element's `field0` value — which is exactly where I put my ROP chain. So the moment my fake vtable entry gets called, EBP is already pointing at my payload. That's what makes the stack pivot below work.

## The payload: pivot, then ROP

My fake vtable's one live entry is a `mov esp, ebp ; pop ebp ; ret` gadget from kernel32. Since EBP already points at my ROP chain (previous section), this one instruction moves the CPU's stack pointer into my buffer — and from there, every `ret` just walks through my chain.

The chain itself does three things, in order:
1. Reads the handle for `C:\flag.txt` (the server already has it open — it's sitting in a global variable).
2. Calls `kernel32!ReadFile` on it, reading into some scratch space I picked out (a chunk of `.data` nothing else in the binary touches).
3. Calls the binary's own "send 18 bytes" helper a few times to send the file contents back over the same socket.

There's one other note: the chain needs to hand `ReadFile` the flag handle as an argument, but it doesn't know its own address ahead of time (it's sitting in a heap allocation, so its address depends on how the grooming went). So the chain computes its own address mid-flight (grab the current stack pointer, add a fixed offset) and patches the argument in, right before `ReadFile` reads it.

## Dealing with ASLR

Both `lfh.exe` and `kernel32.dll` load at a randomized address every boot, and the ROP chain above needs real addresses for both. Since I'm running the target myself, I don't need a leak to figure out where they landed — load the binary in WinDbg by attaching to the running process to determine base address. Windows also only re-randomizes this once per boot, not per process launch, so I only have to ask once and it's good until the machine reboots.

I did implement determining the base address by utilizing the leak to demonstrate how this is done, but this is a brute force and isn't

## Why it doesn't work every time

Here's the thing about that `-5` index: it's guaranteed to land on *some* real chunk boundary. Whether that chunk happens to be a live `OneObject`, though, is not guaranteed — the heap deliberately randomizes which chunk ends up where within a bucket, specifically to make this exact kind of trick unreliable (this has been a Windows security hardening feature since Windows 8).

So the exploit retries: spin up a fresh connection, groom, fire, see if it worked. Originally that landed about 1 time in 24 — workable, but I figured we could do better. Turns out we could, easily: instead of grooming just one `OneObject` before firing, groom a bunch of them. More live targets means better odds that whichever chunk ends up 2 slots back is one of mine. After testing — 22 objects gets us to about 90%.

Going over 22 objects makes the odds of hitting drop to near zero. Apparently in this particular bucket only 22 objects can be allocated, anymore and a new bucket is used.
## Running it

```
python exploit/solver.py
```

This spins up `lfh.exe` locally, connects, and starts trying. It usually lands on the first or second try; if you do see a failure, that's expected, not a bug — the server just exits when the write misses. Eventually:

```
[+] flag: b'flag{must_be_a_197_iq_hacker}'
```

## Further reading


- `docs/challenge-writeup.md` — the full technical writeup, evidence-cited, organized by concept.
- `docs/exploit-explained.md` — same story as above but with memory diagrams and a presentation-style Q&A.
- `docs/solver-line-by-line.md` — every line of `exploit/solver.py` explained.
- `docs/findings.md` — the fact-by-fact log, if you want to know exactly how confident we are about any given claim and why.
- `docs/todo.md` — the couple of things I never fully nailed down (mainly: the exact algorithm Windows uses to pick which chunk goes where — I know *that* it's randomized and roughly when that hardening was added, just not the precise mechanism for this specific heap variant).