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
(now saved locally at `references/Understanding_the_LFH.pdf` — this one *does* document the
right heap manager for `lfh.exe` (classic NT Heap), unlike the Segment Heap paper below; see
`docs/findings.md` "Classic NT Heap LFH internals" for what it explains about this exploit,
including a full derivation of why `OOB_INDEX = -5` specifically)

https://github.com/saaramar/Deterministic_LFH

[Windows 8 Internals](https://media.blackhat.com/bh-us-12/Briefings/Valasek/BH_US_12_Valasek_Windows_8_Heap_Internals_Slides.pdf)

[Windows 10 Segment Heap](https://blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals.pdf)
(now saved locally at `references/us-16-Yason-Windows-10-Segment-Heap-Internals-wp.pdf` —
note this documents a *different* heap manager than the one `lfh.exe` actually uses; see
`docs/findings.md` "Heap manager identity" for why classic NT Heap's LFH, not Segment Heap,
applies here)

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

- Lateron, we can see that the server is expecting a string immediately following the '1':
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
	/* 0x00 */ int probable_vtable;
	/* 0x04 */ char unknown[24];
	/* 0x1c */ char *buffer;
}
```
## Global state

This function uses a global index table variable that behaves like a ring buffer. After 256 insertions the index wraps. Object replacement behavior has not yet been fully analyzed. The global index table is statically allocated with a length of 256.
![[Pasted image 20260506205508.png]]
![[Pasted image 20260506205614.png]]
The dynamically allocated string buffer remains referenced by the OneObject object through the global index table.
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
| oneObj         | command '1'       | ?            | aPtrIndex     |
| fourObj.field0 | recvToBuff (safe) | cleanup Loop | fourObj       |
| fourObj.fieldC | recvToBuff (safe) | cleanup loop | fourObj       |
- take 18 allocations to activate LFH
- so we need at lesat 18 allocations of 0x20
- then we should see the LFH active in Windbg