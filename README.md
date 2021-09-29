# Faulty isogenies

We centered on injecting faults on the curve coefficients from isogeny chains.
Our attack is slightly different from Yan Bo Ti's attack (faults injected on the points).
In particular, we attack 3-isogeny chains (our results can be easily adapted to 2-isogeny chains).

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
./sidh434_fault/test_SIDH
# SIKEp503
./sidh510_fault/test_SIDH
# SIKEp610
./sidh610_fault/test_SIDH
# SIKEp751
./sidh751_fault/test_SIDH
```

## Cleaning
```
make clean
```

## Benchmarks

The SW implementation simulates the fault injection, and fully recover Bob's private key

```bash
$ ./sidh434_fault/test_SIDH

+++	Recovering Bob's private key
+++	Bobₛₖ : k₀ + k₁3 + k₂3² + ... + kₙ3ⁿ
+++	Key recovery printing: k₀k₁k₂...kₙ

[100%] All experiments PASSED
	Attack runs in ...............................      10623 millions of cycles
	Attack performs ..............................        342 oracle calls 
$ ./sidh503_fault/test_SIDH

+++	Recovering Bob's private key
+++	Bobₛₖ : k₀ + k₁3 + k₂3² + ... + kₙ3ⁿ
+++	Key recovery printing: k₀k₁k₂...kₙ

[100%] All experiments PASSED
	Attack runs in ...............................      17839 millions of cycles
	Attack performs ..............................        397 oracle calls 
$ ./sidh610_fault/test_SIDH

+++	Recovering Bob's private key
+++	Bobₛₖ : k₀ + k₁3 + k₂3² + ... + kₙ3ⁿ
+++	Key recovery printing: k₀k₁k₂...kₙ

[100%] All experiments PASSED
	Attack runs in ...............................      42880 millions of cycles
	Attack performs ..............................        481 oracle calls 
$ ./sidh751_fault/test_SIDH

+++	Recovering Bob's private key
+++	Bobₛₖ : k₀ + k₁3 + k₂3² + ... + kₙ3ⁿ
+++	Key recovery printing: k₀k₁k₂...kₙ

[100%] All experiments PASSED
	Attack runs in ...............................      98381 millions of cycles
	Attack performs ..............................        599 oracle calls 
```
