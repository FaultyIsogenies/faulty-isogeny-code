# Faulty isogenies: a new kind of leakage

## Cloning the repository

```bash
# Cloning including the submodule
git clone --recurse-submodules git@github.com:FaultyIsogenies/faulty-isogeny-code.git
```

## Compiling

The way for compiling is teh same as the [SIDH Library](https://github.com/microsoft/PQCrypto-SIDH).
However, we summarizes how to compile our implementation (options `ARCH=[ARM64/ARM/s390x]` not tested
yet, but they should work).

```bash
# Compiling for SIKEp434, SIKEp503, SIKEp610, and SIKEp751 (current SIDH v3.4 code [C Edition])
# Just run
make -B ARCH=[x86/x64] CC=[gcc/clang] OPT_LEVEL=[FAST/GENERIC]
# By default, OPT_LEVEL=FAST, ARCH=x64
make -B
```

## Testing

```
# SIKEp434
./sidh434_attack/test_SIDH
# SIKEp503
./sidh510_attack/test_SIDH
# SIKEp610
./sidh610_attack/test_SIDH
# SIKEp751
./sidh751_attack/test_SIDH
```

## Cleaning
```
make clean
```

## Benchmarks

The SW implementation simulates the fault injection, and fully recover Bob's private key

```bash
$ ./sidh434_attack/test_SIDH 

+++	Recovering Bob's private key
+++	Bobₛₖ : k₀ + k₁3 + k₂3² + ... + kₙ3ⁿ
+++	Key recovery printing: k₀k₁k₂...kₙ

[100%] All experiments PASSED
	Attack runs in ...............................       4980 millions of cycles
	Attack performs ..............................        225 oracle calls 
	
$ ./sidh503_attack/test_SIDH

+++	Recovering Bob's private key
+++	Bobₛₖ : k₀ + k₁3 + k₂3² + ... + kₙ3ⁿ
+++	Key recovery printing: k₀k₁k₂...kₙ

[100%] All experiments PASSED
	Attack runs in ...............................       9344 millions of cycles
	Attack performs ..............................        261 oracle calls 
	
$ ./sidh610_attack/test_SIDH

+++	Recovering Bob's private key
+++	Bobₛₖ : k₀ + k₁3 + k₂3² + ... + kₙ3ⁿ
+++	Key recovery printing: k₀k₁k₂...kₙ

[100%] All experiments PASSED
	Attack runs in ...............................      21840 millions of cycles
	Attack performs ..............................        319 oracle calls 
	
$ ./sidh751_attack/test_SIDH

+++	Recovering Bob's private key
+++	Bobₛₖ : k₀ + k₁3 + k₂3² + ... + kₙ3ⁿ
+++	Key recovery printing: k₀k₁k₂...kₙ

[100%] All experiments PASSED
	Attack runs in ...............................      49672 millions of cycles
	Attack performs ..............................        397 oracle calls 
```
