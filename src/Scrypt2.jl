module Scrypt2

export ScryptParameters, scrypt, scrypt_threaded

using PrecompileTools
using Nettle
using Nettle_jll
using Base.Threads

include("ScryptParameters.jl")

const HASH_LENGTH::Int = 256 ÷ 8
const SALSA_BLOCK_REORDER_INDEXES = Int[13, 2, 7, 12, 1, 6, 11, 16, 5, 10, 15, 4, 9, 14, 3, 8]
const EMPTY_SALT = Vector{UInt8}()

"""
    scrypt(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer)
    scrypt(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer)

Return a derived key of length `derivedkeylength` bytes, derived from the given `key` and optional `salt`, using the scrypt key derivation function with the specified `parameters`.

See also: multi-threaded [`scrypt_threaded`](@ref).
"""
function scrypt(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer)
    derivedkeylength > 0 || throw(ArgumentError("Must be > 0."))

    buffer = pbkdf2_sha256_1(key, salt, bufferlength(parameters))
    parallelbuffer = unsafe_wrap(Array{UInt32,3}, Ptr{UInt32}(pointer(buffer)), (16, elementblockcount(parameters), parameters.p));

    workingbuffer_new = Matrix{UInt32}(undef, (16, elementblockcount(parameters)))
    shufflebuffer_new = Matrix{UInt32}(undef, (16, elementblockcount(parameters)))
    scryptblock_new = Array{UInt32,3}(undef, 16, 2*parameters.r, parameters.N);

    for i ∈ 1:parameters.p
        element_new = @view(parallelbuffer[:, :, i])
        smix_new!(scryptblock_new, workingbuffer_new, shufflebuffer_new, element_new, parameters)
    end

    derivedkey = pbkdf2_sha256_1(key, buffer, derivedkeylength)
end
function scrypt(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer)
    scrypt(parameters, key, EMPTY_SALT, derivedkeylength)
end

"""
    scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer)
    scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer)

Return a derived key of length `derivedkeylength` bytes, derived from the given `key` and optional `salt`, using the scrypt key derivation function with the specified `parameters`.

It uses `Base.Threads` to parallelize the computation if `parameters.p > 1`. To use `JobSchedulers.jl` for parallelization, please load the package and use the `scrypt_threaded` function with the `job_priority` argument.

See also: single-threaded [`scrypt`](@ref).
"""
function scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer)
    derivedkeylength > 0 || throw(ArgumentError("Must be > 0."))

    buffer = pbkdf2_sha256_1(key, salt, bufferlength(parameters))
    parallelbuffer = unsafe_wrap(Array{UInt32,3}, Ptr{UInt32}(pointer(buffer)), (16, elementblockcount(parameters), parameters.p));

    @threads for i ∈ 1:parameters.p
        workingbuffer_new = Matrix{UInt32}(undef, (16, elementblockcount(parameters)))
        shufflebuffer_new = Matrix{UInt32}(undef, (16, elementblockcount(parameters)))
        scryptblock_new = Array{UInt32,3}(undef, 16, 2*parameters.r, parameters.N);

        element_new = @view(parallelbuffer[:, :, i])
        smix_new!(scryptblock_new, workingbuffer_new, shufflebuffer_new, element_new, parameters)
    end

    derivedkey = pbkdf2_sha256_1(key, buffer, derivedkeylength)
end
function scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer)
    scrypt_threaded(parameters, key, EMPTY_SALT, derivedkeylength)
end


function pbkdf2_sha256_1(key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Int)
    salt_new = copy(salt)
    _pbkdf2_sha256_1(key, salt_new, derivedkeylength)
end

function pbkdf2_sha256_1(key::Vector{UInt8}, derivedkeylength::Int)
    _pbkdf2_sha256_1(key, Vector{UInt8}(), derivedkeylength)
end

@inline function _pbkdf2_sha256_1(key::Vector{UInt8}, salt_new::Vector{UInt8}, derivedkeylength::Int)
    blockcount = cld(derivedkeylength, HASH_LENGTH)::Int
    
    push!(salt_new, 0x00, 0x00, 0x00, 0x00)
    
    derivedkey::Vector{UInt8} = Vector{UInt8}(undef, (HASH_LENGTH * blockcount)::Int);
    p_derivedkey = pointer(derivedkey)::Ptr{UInt8}

    state = Nettle.HMACState("SHA256", key)
    for i in 1:blockcount
        salt_tail_reverse!(salt_new, i)
        unsafe_digest!(p_derivedkey + (i - 1) * HASH_LENGTH, Csize_t(HASH_LENGTH), Nettle.update!(state, salt_new))
    end
    resize!(derivedkey, derivedkeylength)
    return derivedkey
end

@inline function salt_tail_reverse!(salt::Vector{UInt8}, i::Int)
    # reinterpret(UInt8, [UInt32(i)]) |> reverse
    u32 = UInt32(i)
    @inbounds salt[end] = u32 % UInt8
    u32 >>= 8
    @inbounds salt[end - 1] = u32 % UInt8
    u32 >>= 8
    @inbounds salt[end - 2] = u32 % UInt8
    u32 >>= 8
    @inbounds salt[end - 3] = u32 % UInt8
    nothing
end

@inline function unsafe_digest!(digest_block::Ptr{UInt8}, block_size::Csize_t, state::Nettle.HMACState)
    # @boundscheck checkbounds(digest_block, state.hash_type.digest_size)
    ccall((:nettle_hmac_digest,libnettle), Cvoid, (Ptr{Cvoid},Ptr{Cvoid},Ptr{Cvoid},Ptr{Cvoid}, Csize_t,
        Ptr{UInt8}), state.outer, state.inner, state.state, state.hash_type.ptr, block_size, digest_block)
    return digest_block
end

function smix_new!(scryptblock_new::Array{UInt32, 3}, workingbuffer_new::Matrix{UInt32}, shufflebuffer_new::Matrix{UInt32}, element_new::AbstractArray{UInt32, 2}, parameters::ScryptParameters)
    prepare_new!(workingbuffer_new, element_new) #ok
    scryptblock_new, workingbuffer_new, shufflebuffer_new = fillscryptblock_new!(scryptblock_new, workingbuffer_new, shufflebuffer_new, parameters.r, parameters.N)
    workingbuffer_new = mixwithscryptblock_new!(workingbuffer_new, scryptblock_new, shufflebuffer_new, parameters.r, parameters.N)
    restore_new!(element_new, workingbuffer_new)
end

@inline function prepare_new!(dest::Matrix{UInt32}, src::AbstractArray{UInt32, 2})
    ysize = size(src, 2)

    @inbounds dest[:, 1] = @view src[SALSA_BLOCK_REORDER_INDEXES, ysize]
    @inbounds for i in 1:ysize-1
        dest[:, i+1] = @view src[SALSA_BLOCK_REORDER_INDEXES, i]
    end

    return dest
end

@inline function restore_new!(dest::AbstractMatrix{UInt32}, src::AbstractMatrix{UInt32})

    # for (i, j) ∈ zip(si, dj)
    @inbounds dest[SALSA_BLOCK_REORDER_INDEXES, end] = @view src[:, 1]
    ysize = size(src, 2)
    @inbounds for i in 2:ysize
         dest[SALSA_BLOCK_REORDER_INDEXES, i-1] = @view src[:, i]
    end
    return dest
end

@inline function fillscryptblock_new!(scryptblock_new::Array{UInt32, 3}, workingbuffer_new::Matrix{UInt32}, shufflebuffer_new::Matrix{UInt32}, r::Int, N::Int) 
    # inplace edit: block_new (workingbuffer_new), shufflebuffer_new[:,i] (stored as final)
    @inbounds for i ∈ 1:N
        scryptelement_new = view(scryptblock_new, :, :, i)
        previousblock_new = @view workingbuffer_new[:, 1]
        scryptelement_new[:, 1] .= previousblock_new
        @inbounds for j ∈ 2:2r
            block_new = @view workingbuffer_new[:, j] #ok
            scryptelement_new[:, j] .= block_new

            mixblock_shuffle_store_new!(block_new, previousblock_new, shufflebuffer_new, shuffleposition(j, r))
            previousblock_new = block_new
        end
        block_new = @view workingbuffer_new[:, 1]
        mixblock_shuffle_store_new!(block_new, previousblock_new, shufflebuffer_new, 1)
        workingbuffer_new, shufflebuffer_new = shufflebuffer_new, workingbuffer_new
    end
    return scryptblock_new, workingbuffer_new, shufflebuffer_new
end

@inline shuffleposition(j::Int, halfblockcount::Int) = (j - 2) ÷ 2 + 2 + (iseven(j) ? 0 : halfblockcount)

@inline function mixwithscryptblock_new!(workingbuffer_new::Matrix{UInt32}, scryptblock_new::Array{UInt32,3}, shufflebuffer_new::Matrix{UInt32}, r::Int, N::Int)
    previousblock_new = Vector{UInt32}(undef, 16);
    lastblock_new = Vector{UInt32}(undef, 16);
    block_new = Vector{UInt32}(undef, 16);
    @inbounds for _ ∈ 1:N
        n = integerify(workingbuffer_new, N)
        scryptelement_new = view(scryptblock_new, :, :, n)

        @inbounds for m in 1:16  # load_xor
            previousblock_new[m] = lastblock_new[m] = workingbuffer_new[m, 1] ⊻ scryptelement_new[m, 1]
        end

        for j ∈ 2:2r
            @inbounds for m in 1:16
                block_new[m] = workingbuffer_new[m, j] ⊻ scryptelement_new[m, j]
            end

            block_new = mixblock_shuffle_store_new!(block_new, previousblock_new, shufflebuffer_new, shuffleposition(j, r))
            previousblock_new .= block_new
        end
        mixblock_shuffle_store_new!(lastblock_new, previousblock_new, shufflebuffer_new, 1)
        workingbuffer_new, shufflebuffer_new = shufflebuffer_new, workingbuffer_new
    end
    return workingbuffer_new
end

@inline integerify(x::Matrix{UInt32}, N::Int) = @inbounds x[5,1] % N + 1

"""
inplace edit: `block_new`, `shufflebuffer_new[:,i]`
not edit: `previousblock_new`
"""
@inline function mixblock_shuffle_store_new!(block_new::AbstractVector{UInt32}, previousblock_new::AbstractVector{UInt32}, shufflebuffer_new::Matrix{UInt32}, i::Int)
    block_new .⊻= previousblock_new
    # block_new_good = deepcopy(block_new)
    salsa20_new!(shufflebuffer_new, i, block_new, 8)
    return block_new
end

@inline function salsa20_new!(shufflebuffer_new::Matrix{UInt32}, i::Int, block_new::AbstractVector{UInt32}, iterations::Int)
    @inbounds shufflebuffer_new[:, i] = block_new

    line1 = @inbounds @view block_new[1:4]
    line2 = @inbounds @view block_new[5:8]
    line3 = @inbounds @view block_new[9:12]
    line4 = @inbounds @view block_new[13:16]
    for _ ∈ 1:iterations
        salsamix!(line1, line2, line3, line4)
        salsatranspose!(block_new)
    end

    block_new .+= @inbounds @view shufflebuffer_new[:, i]
    @inbounds shufflebuffer_new[:, i] = block_new
end

@inline function salsamix!(line1::T, line2::T, line3::T, line4::T) where T<:AbstractArray{UInt32}
    # salsa!: the third argument is modified in place
    salsa!(line1, line2, line3, 7)
    salsa!(line2, line3, line4, 9)
    salsa!(line3, line4, line1, 13)
    salsa!(line4, line1, line2, 18)
end

@eval @inline function salsa!(addend1::T, addend2::T, xor_operand::T, rotationmagnitude::Int) where T<:AbstractArray{UInt32}
    # the third argument (xor_operand) is modified in place.
    # the following is the expansion of @simd ivdep for loop. @simd macro expansion is heavy, and the following is simplified for better performance.
    idx = 0
    @inbounds while idx < 4
        idx += 1
        sumtmp = addend1[idx] + addend2[idx]
        xor_operand[idx] ⊻= sumtmp << rotationmagnitude | sumtmp >>> (32 - rotationmagnitude)
        $(Expr(:loopinfo, Symbol("julia.simdloop"), Symbol("julia.ivdep")))
    end

    # @simd ivdep for i in eachindex(xor_operand)
    #     sumtmp = addend1[i] + addend2[i]
    #     xor_operand[i] ⊻= (sumtmp << rotationmagnitude) | (sumtmp >>> (32 - rotationmagnitude))
    # end
    return xor_operand
end

"""
    salsatranspose!(v::AbstractVector{UInt32})
In-place transpose of the 16-element vector `v`. Similar to the following operation:

```julia
const SALSA_TRANSPOSE_INDEXES = [
    12,9,10,11,
    5,6,7,8,
    2,3,4,1,
    15,16,13,14
]
v = v[SALSA_TRANSPOSE_INDEXES]
```
"""
@inline function salsatranspose!(v::AbstractVector{UInt32})
    @inbounds begin
        a1 = v[1]
        a2 = v[2]
        a3 = v[3]
        a4 = v[4]
        # 5:8 not changed
        a9 = v[9]
        a10 = v[10]
        a11 = v[11]
        a12 = v[12]
        a13 = v[13]
        a14 = v[14]
        a15 = v[15]
        a16 = v[16]
        v[1] = a12
        v[2] = a9
        v[3] = a10
        v[4] = a11
        # 5:8 not changed
        v[9] = a2
        v[10] = a3
        v[11] = a4
        v[12] = a1
        v[13] = a15
        v[14] = a16
        v[15] = a13
        v[16] = a14
    end
    v
end

include("precompile.jl")

end  # module Scrypt2
