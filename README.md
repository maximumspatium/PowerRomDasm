# PowerRomDasm

An attempt to disassemble a Power Macintosh ROM using widely available disassemblers
will likely lead to disappointing results. While some state-of-the-art disassemblers
employ various heurictics for distinguishing embedded data from executable code,
a lot of additional manual work still need to be done to produce a nice disassembly.
Additionally, Power Macintosh ROMs contain code for several CPU architectures
(68k, PowerPC, FCode) so a multi-architecture disassembler is required for telling
all this stuff apart.

The purpose of this repository is to provide a tool for producing a nice disassembly
for the existing Power Macintosh ROM dumps annotated with various symbols like
function names, entry points etc. The resulting text dump can be used for easier debugging
of MacOS system software and emulator development.

## Prerequisites

The following components are required to run PowerRomDasm:
- Python 3
- Python bindings for [Capstone disassembler framework](https://www.capstone-engine.org)

## Usage

```
python3 PowerRomDasm.py --rom_path=[path to a Power Macintosh ROM dump] --start=0 --end=0x300
