# Scrypt2.jl

[![Build Status](https://github.com/cihga39871/Scrypt.jl/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/cihga39871/Scrypt.jl/actions/workflows/CI.yml?query=branch%3Amain)

Scrypt is a password-based key derivation function (KDF) designed to be **memory-hard** and **computationally expensive**, making it significantly more resistant to brute-force attacks and hardware-accelerated cracking (especially GPU/ASIC attacks) compared to earlier functions like PBKDF2, bcrypt, or SHA-256.

This package is a rewritten version of Nicholas Bauer's [Scrypt.jl](https://github.com/BioTurboNick/Scrypt.jl). I would like to thank Nicholas for making his original work open source — without it, this package would not have been possible.

The package uses the same algorithm as Scrypt.jl, but improves speed and RAM allocations (see consistency test and benchmark at the end of README). Besides, Scrypt2 also supports multi-threading using `Base.Threads` or [`JobSchedulers.jl`](https://github.com/cihga39871/JobSchedulers.jl).

## Quick Usage

```julia
using Scrypt2

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
- `p::Int`: Parallelization factor. How many independent tasks can run at the same time. Higher p = uses more CPU cores, but also multiplies the total memory needed. Must be > 0.

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

Note: The following methods are only available when you `using JobSchedulers`.

```julia
scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer, job_priority::Int)
scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer, job_priority::Int)
```

- `job_priority::Int`: The priority of the jobs created for parallel execution. Lower values indicate higher priority. The default priority of regular jobs is `20`.

It uses `JobSchedulers.jl` to parallelize the computation if `parameters.p > 1`. To use `Base.Threads` for parallelization, please use the `scrypt_threaded` function without the `job_priority` argument.

## Consistency with Scrypt.jl

The consistency is tested with the following scrypt:

```julia
# julia -t 16
import Scrypt
import Scrypt2
using Test

function consistency_test(r::Int, N::Int, p::Int; num_test=100) # r,N,p: Scrypt parameters
    param = Scrypt.ScryptParameters(r,N,p)
    param2 = Scrypt2.ScryptParameters(r,N,p)

    @testset "Scrypt Consistency Tests: 1, 6, 1" begin
        for i in 1:100
            key = rand(UInt8, rand(1:128))
            salt = rand(UInt8, rand(0:64))
            dklen = rand(16:128)

            old = Scrypt.scrypt(param, key, salt, dklen)
            if p == 1
                new = Scrypt2.scrypt(param2, key, salt, dklen)
            else
                new = Scrypt2.scrypt_threaded(param2, key, salt, dklen)
            end

            @test old == new
        end
    end
end

@testset "Scrypt Consistency Tests" begin
    consistency_test(1, 16, 1; num_test=100)
    consistency_test(2, 32, 2; num_test=100)
    consistency_test(8, 1024, 16; num_test=50)
    consistency_test(8, 16384, 1; num_test=10)
    consistency_test(8, 1048576, 1; num_test=3)
end
    


```
