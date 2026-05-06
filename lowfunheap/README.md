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
