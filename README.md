# Scrypt2.jl

[![Build Status](https://github.com/cihga39871/Scrypt.jl/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/cihga39871/Scrypt.jl/actions/workflows/CI.yml?query=branch%3Amain)

Scrypt is a **memory-hard** password-based key derivation algorithm designed to make brute-force attacks expensive in both CPU and RAM usage.

This package is re-written from Nicholas Bauer's [Scrypt.jl](https://github.com/BioTurboNick/Scrypt.jl). I appreciate it and without his open-sourced code, Scrypt2 will not be written.

The package uses the same algorithm as Scrypt.jl, but improves speed and RAM usage. Besides, Scrypt2 also supports multi-threading using `Base.Threads` or [`JobSchedulers.jl`](https://github.com/cihga39871/JobSchedulers.jl).

## Usage

