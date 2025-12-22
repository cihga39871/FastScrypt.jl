# FastScrypt.jl

[![Build Status](https://github.com/cihga39871/Scrypt.jl/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/cihga39871/Scrypt.jl/actions/workflows/CI.yml?query=branch%3Amain)

Scrypt is a password-based key derivation function (KDF) designed to be **memory-hard** and **computationally expensive**, making it significantly more resistant to brute-force attacks and hardware-accelerated cracking (especially GPU/ASIC attacks) compared to earlier functions like PBKDF2, bcrypt, or SHA-256.

This package is a rewritten version of Nicholas Bauer's [Scrypt.jl](https://github.com/BioTurboNick/Scrypt.jl). I would like to thank Nicholas for making his original work open source — without it, this package would not have been possible.

The package uses the same algorithm as Scrypt.jl, and

- improves speed (**>2X faster**) and RAM allocations (see benchmark at the end of README);
- supports **multi-threading** using `Base.Threads` or [`JobSchedulers.jl`](https://github.com/cihga39871/JobSchedulers.jl).

## Quick Usage

```julia
using FastScrypt

r = 8
N = 16384
p = 1
key = Vector{UInt8}(b"pleaseletmein")
salt = Vector{UInt8}(b"SodiumChloride")
derivedkeylength = 64 # length of the returned derived key

scrypt(ScryptParameters(r, N, p), key, salt, derivedkeylength)
# 64-element Vector{UInt8}:
#  0x70
#  0x23
#  0xbd
#     ⋮
#  0x58
#  0x87
```

## API

### `ScryptParameters`

```julia
ScryptParameters(r::Int, N::Int, p::Int)
```

A struct to hold Scrypt parameters.

Parameters:

- `r::Int`: Block size factor. Affects how much memory is used per "chunk" of work. Must be > 0.
- `N::Int`: CPU/Memory cost factor. The biggest number — controls how much memory and time the function uses. Higher N = more secure, but also slower and uses more memory. Must be a power of 2, > 1.
- `p::Int`: Parallelization factor. How many independent tasks can run at the same time. Higher p = uses more CPU cores, but also multiplies the total memory. Must be > 0.

Note: In FastScrypt.jl, if you use single-threaded `scrypt` with `p>1`, memory buffer will be reused, so the peak memory is roughly `1/p` of parallel version `scrypt_threaded`.

### `scrypt`

```julia
scrypt(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer)
scrypt(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer)
```

Return a derived key of length `derivedkeylength` bytes, derived from the given `key` and optional `salt`, using the scrypt key derivation function with the specified `parameters`.

### `scrypt_threaded` (parallel using Base.Threads)

```julia
scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer)
scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer)
```

It uses `Base.Threads` to parallelize the computation if `parameters.p > 1`.

### `scrypt_threaded` (parallel using JobSchedulers package)

> **Compat:** The following methods are only available for Julia version >=v1.9.0 and when you `using JobSchedulers`.

```julia
scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer, job_priority::Int)
scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer, job_priority::Int)
```

- `job_priority::Int`: The priority of the jobs created for parallel execution. Lower values indicate higher priority. The default priority of regular jobs is `20`.

It uses `JobSchedulers.jl` to parallelize the computation if `parameters.p > 1`. To use `Base.Threads` for parallelization, please use the `scrypt_threaded` function without the `job_priority` argument.

## Consistency and Speed Benchmark with Scrypt.jl

Test using Julia v1.12.1 (20 threads), Scrypt v0.2.1, FastScrypt v1.0.0.

The general concept is to test different parameters with random keys and salts, and compute the average time and memory used for each scrypt function.

Test script is as follows:

```julia
# julia -t 20

import Scrypt
import FastScrypt
using Test

function gcdff_add(a::Base.GC_Diff, b::Base.GC_Diff)
    Base.GC_Diff((getfield(a, f) + getfield(b, f) for f in fieldnames(Base.GC_Diff))...)
end

function timed_add(a, b)
    return (
        time = a.time + b.time,
        bytes = a.bytes + b.bytes,
        gctime = a.gctime + b.gctime,
        gcstats = gcdff_add(a.gcstats, b.gcstats),
        lock_conflicts = a.lock_conflicts + b.lock_conflicts,
        compile_time = a.compile_time + b.compile_time,
        recompile_time = a.recompile_time + b.recompile_time
    )
end

function timed_avg(a, num_test::Int)
    return (
        time = a.time / num_test,
        bytes = a.bytes ÷ num_test,
        gctime = a.gctime / num_test,
        gcstats = Base.GC_Diff((getfield(a.gcstats, f) ÷ num_test for f in fieldnames(Base.GC_Diff))...),
        lock_conflicts = a.lock_conflicts ÷ num_test,
        compile_time = a.compile_time / num_test,
        recompile_time = a.recompile_time / num_test
    )
end

function consistency_test_and_benchmark(r::Int, N::Int, p::Int; num_test=100) # r,N,p: Scrypt parameters
    param = Scrypt.ScryptParameters(r,N,p)
    param2 = FastScrypt.ScryptParameters(r,N,p)

    old_timed_add = @timed nothing
    new_timed_add = @timed nothing
    new_threaded_timed_add = @timed nothing

    @testset "Scrypt Consistency Tests: ScryptParameters($r, $N, $p)" begin
        for i in 1:num_test
            key = rand(UInt8, rand(1:128))
            salt = rand(UInt8, rand(0:64))
            dklen = rand(16:128)

            old = @timed Scrypt.scrypt(param, key, salt, dklen)
            new = @timed FastScrypt.scrypt(param2, key, salt, dklen)

            @test old.value == new.value

            old_timed_add = timed_add(old_timed_add, old)
            new_timed_add = timed_add(new_timed_add, new)

            if p > 1
                new_threaded = @timed FastScrypt.scrypt_threaded(param2, key, salt, dklen)
                @test new.value == new_threaded.value
                new_threaded_timed_add = timed_add(new_threaded_timed_add, new_threaded)
            end
        end
    end
    
    old = timed_avg(old_timed_add, num_test)
    new = timed_avg(new_timed_add, num_test)
    diff = round(old.time / new.time; digits=2)

    println(Base.stdout, "ScryptParameters($r, $N, $p):")
    println(Base.stdout, "  $(diff)X faster")
    Base.time_print(Base.stdout, old.time * 1.0e9, old.gcstats.allocd, old.gcstats.total_time, Base.gc_alloc_count(old.gcstats), old.lock_conflicts, old.compile_time * 1.0e9, old.recompile_time * 1.0e9, true; msg = "  old           ")
    Base.time_print(Base.stdout, new.time * 1.0e9, new.gcstats.allocd, new.gcstats.total_time, Base.gc_alloc_count(new.gcstats), new.lock_conflicts, new.compile_time * 1.0e9, new.recompile_time * 1.0e9, true; msg = "  new           ")

    if p > 1
        new_threaded = timed_avg(new_threaded_timed_add, num_test)
        Base.time_print(Base.stdout, new_threaded.time * 1.0e9, new_threaded.gcstats.allocd, new_threaded.gcstats.total_time, Base.gc_alloc_count(new_threaded.gcstats), new_threaded.lock_conflicts, new_threaded.compile_time * 1.0e9, new_threaded.recompile_time * 1.0e9, true; msg = "  new (threaded)")
    end
    println()
end

@testset "Scrypt Consistency Tests" begin
    consistency_test_and_benchmark(1, 16, 1; num_test=100)
    consistency_test_and_benchmark(8, 1024, 16; num_test=50)
    consistency_test_and_benchmark(8, 16384, 1; num_test=50)
    consistency_test_and_benchmark(8, 1048576, 1; num_test=3)
end;
```

Results:

```julia
ScryptParameters(1, 16, 1)
  2.42X faster
  old           : 0.000021 seconds (165 allocations: 32.411 KiB)
  new           : 0.000009 seconds (51 allocations: 5.779 KiB)

ScryptParameters(8, 1024, 16)
  2.54X faster
  old           : 0.088445 seconds (11.29 k allocations: 20.903 MiB, 3.33% gc time)
  new           : 0.034788 seconds (145 allocations: 1.082 MiB, 0.33% gc time)
  new (threaded): 0.005224 seconds (352 allocations: 16.124 MiB, 21.43% gc time)

ScryptParameters(8, 16384, 1)
  2.23X faster
  old           : 0.088902 seconds (753 allocations: 16.076 MiB, 1.69% gc time)
  new           : 0.039811 seconds (53 allocations: 16.009 MiB, 4.51% gc time)

ScryptParameters(8, 1048576, 1)
  2.09X faster
  old           : 5.808510 seconds (760 allocations: 1.000 GiB, 0.84% gc time)
  new           : 2.773725 seconds (53 allocations: 1.000 GiB, 2.65% gc time)

Test Summary:            | Pass  Total   Time
Scrypt Consistency Tests |  253    253  38.6s
```