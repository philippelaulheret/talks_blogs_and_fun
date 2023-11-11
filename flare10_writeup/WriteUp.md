# Flare-On 10 - Process and comments

## Introduction

I've been playing/finishing Flare-On for the last 6 years or so and this year I felt like writing about some of it. But looking back at my "ctf/flareon10" folder I realize I don't feel like going over the exercise of writing up in detail the solution for all/any of the challenges. Instead, I'm going to share here the process I went through, and any relevant tidbits that were interesting to note. I'm also going to share the scripts I've used to clean up the last challenges. I did it two different ways (the wrong way and the other ;D). See [here](DeobfuscatingChal13.md) for the details about that. 

If you're an expert reverser, feel free to skip to the [Tips and tricks](#Tips-and-tricks) section, but if you're newer at reversing/the Flare-On CTF and curious about someone's process, maybe this document will be of interest. 

## Setup 

My setup is as follows: 
- Host PC running Windows, IDA Free on it. Trying to avoid running any code/sketchy python scripts. VsCode / Notepad++ / Hex editor. 
- Virtual Box VMs:
    - Linux (Ubuntu) with all necessary tools installed as I go / need them (jd-gui, jadx, binwalk, qemu, keystone/capstone, pwntools, ghidra, qemu, ... )
    - Windows 11 VM (see [here](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)). There are automated tools to populate the VM (e.g. search FLARE VM) but I didn't feel like using that so I manually downloaded what I wanted (x64dbg, windbg, some hex editor, notepad++, the VM linked above also comes preinstalled with VS). 
    - A good thing to do (at your own risk, if you're going to run malicious code in a VM) is to enable clipboard sharing and shared folders to copy files more easily between VMs (drag and drop is unreliable, so shared folders is usually my preferred way to go). 

### The tools I use
When it comes to reverse engineering, I much prefer `IDA Free` (ideally `IDA Pro` but right now I don't have a license for it) which does the job in most situations. `Ghidra`/`cutter` or straight-out `obj-dump` are my backups if the architecture is not supported in `IDA Free`. A draw back of IDA's free version is the lack of `IDAPython` which is a must when it comes to scripting to help the reversing. Standalone Python scripts in conjunction with some IDC scripting can be a decent stopgap when having to rely on IDA Free. 

For the more mundane, I usually use `notepad++` (windows) or `gedit` (linux) to write simple scripts (those aren't necessarily the best to write code, but sometimes one can be stubborn and use the wrong tool for the job), `Visual Studio Code` if it's getting a little more complicated, and `Visual Studio`/`gedit`/`vim+gcc` if I'm going to actually compile stuff. I usually like to write python scripts to help dealing with various tasks at hand (muscle memory for base64/xor strings, and `PyCryptodome`` for the AES/RC4 implementation needs...).

## General strategy

Some people have a shot at finishing the whole CTF in a week end, unfortunately I'm not one of them. So when it comes to winning at Flare-On, instead of hyperfocusing on the scoreboard*, I think it's a way more valuable use of time to leverage the CTF to learn new things and get the motivation to use new tools. 

In that regard, I think it's equally fair to take shortcuts and solve a challenge the "easy" way even if we don't understand 100% of it, or, alternatively, go the less efficient road and try to make sense of most of it. The important is to learn new stuff & have fun after all. 

*: The scoreboard is a good source of motivation to keep going, but some people may spend 12h/day on it, while others may only have evenings or weekends, so a better/worse position on the scoreboard is not really a measure of the value of a participant. Unless they solve it in < 48h then we can all agree they're probably some AI from the future beamed back to our time to hand us our collective asses. 

## Tips and tricks

### IDA Stuff

- Know how to clean up hex-rays output:
    - Create structs and apply them to hex ray output
    - It's possible to create segments with different bitness (16-bit, 32-bit, 64-bit) and import binary blobs into them. It's useful for either importing into IDA a 16-bit binary that wouldn't be supported otherwise, or a stage2 shellcode being decoded at runtime and loaded in memory. 
    - Leveraging `__unused`, `__usercall` and `__spoils` in a function definition keywords can help clean up the decompiled output. In some cases variables can be flagged as undefined because they are stored in an non-standard register that should get clobbered in-between function calls, but if the functions called are not spoiling the register, then informing ida may clean up that warning. 
- The delete function tail / append function tail can be useful to clean up functions when IDA mistakenly add blobs of code into a function they don't belong to / miss blobs of function that should be included. 
- It is possible to create shortcuts for these less common commands, and thus can be used more efficiently if they need to be called many times.
- To import an additional binary file, it works better to provide a Loading segment of 0 and a Loading offset of the address you want the blob to be loaded at. Further, if the segment needs to be created, it will default to a specific bit size which may not match the one you intend to; to avoid problems it may be worth it to create the segment ahead of time and have ida load the data into it instead. 
- The `__noreturn` flag can be applied to a function if it will not return (e.g. will call `ExitProcess` or similar). If IDA labels a function with the `__noreturn` tag incorrectly, removing the tag might not be enough, and you may have to go in the function property (ALT+P in the disassembly view) and uncheck the box there as well. Not doing so may lead to disjointed basic blocks where the `call` instruction will be followed by a `---------` divider.
- It can be useful to show the stack pointer value as seen per IDA (Options->General Options->Analysis->Stack Pointer) to debug alerts about the sp pointer being invalid. An invalid stack pointer can lead to hex-ray referencing the wrong variables in the decompiled output (if the program is using rsp addressing to reference its local variables). 

### A bit of dynamic analysis

I used to try to reverse everything statically and/or reimplement the algorithms (it's a reversing challenge after all), but it gets tedious after a while so this year I've also done the following: 
- Use x64dbg to dump decrypted ressources if it's a one time thing (identify the decrypt function in IDA, put a breakpoint after its invocation, dump the result)
- Copy the output from Hex-rays and compile it in visual studio to have standalone code.
    - Worked a few times, failed a few others. 
    - Sometimes casting/variable size/sign may get in the way
    - Search google for "hex ray defs.h" (or look at https://hex-rays.com/blog/igors-tip-of-the-week-67-decompiler-helpers/) for headers to help the output to actually compile
- When everything fails, an approach that may work is to load the binary in x64dbg and execute the function manually: 
    -  Trigger a breakpoint on the entrypoint of the binary
    -  Set RIP to the start of the function you want to execute
    -  Use the "allocate memory" function from the debugger to create memory region where you can populate the data that will be used by the function
        - AFAIK x64dbg doesn't have a write_memory function, so instead I use python to `binascii.hexlify` the data and then select a large blob of allocated data, right click edit and then paste the hex-encoded data. 
    - Adjust the relevant registers/stack values to make sure the function is receiving the desired arguments. 
    - Execute the function until its return. 

    I used that to decrypt the last part of challenge 11 as reimplementing the pseudo ChaCha code did not work and copy-pasting hex ray output into VS lead to decoding half the flag but then printing garbage :"( 
    
    There are few gotchas for that approach:
    - This approach is pretty unsatisfying as it doesn't scale, but sometimes the dumbest method works the best. 
    - A (better) alternative would be to use Unicorn to emulate that function directly (for an example of this approach, see [this](https://www.trellix.com/assets/docs/atr-library/tr-emulating-code-with-unicorn.pdf) that I wrote about before), or FRIDA to instrument the binary and automatically do what's being done manually in the example above.
    - Both Unicorn/Frida approaches require a bit of overhead to setup the thing correctly, so it's a tradeoff time spent doing the thing manually vs writing the automation for it. 


## More serious scripting

Two of the challenges were obfuscated in a somewhat similar fashion; challenge 5 and 13 both rely on breaking up basic blocks into many chunks and jumping from one block to the next. This has the unfortunate effect of confusing ida/hex-ray into defining many functions and adding some basic block to the wrong function. I solved the first one manually by removing/adding the relevant basic blocks to the correct function (which was tedious and against what I described in the general strategy). 

When challenge 13 showed a similar obfuscation technique, I decided to leverage scripting to automatically clean up the code. To make it easier to reference the scripts, I've written a separate description [here](DeobfuscatingChal13.md). 

TL;DR; with IDA Free it is possible to write IDC scripts but IDA Python was sorely missed. And instead of forcing IDA to process the file correctly, it is easier to just clean up the code by performing what is likely to be the reverse transformation of the original obfuscation. 


## Conclusion

If this rambling was useful but left you with more questions, feel free to reach out (@phLaul on Twitter). 

And remember, what matters is to have fun and learn new stuff!  