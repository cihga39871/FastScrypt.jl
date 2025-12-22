module FastScryptExtJobSchedulers

using JobSchedulers
using FastScrypt

"""
    scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer, job_priority::Int)
    scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer, job_priority::Int)

Return a derived key of length `derivedkeylength` bytes, derived from the given `key` and optional `salt`, using the scrypt key derivation function with the specified `parameters`.

- `job_priority::Int`: The priority of the jobs created for parallel execution. Lower values indicate higher priority. The default priority of regular jobs is `20`.

It uses `JobSchedulers.jl` to parallelize the computation if `parameters.p > 1`. To use `Base.Threads` for parallelization, please use the `scrypt_threaded` function without the `job_priority` argument.
"""
function FastScrypt.scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, salt::Vector{UInt8}, derivedkeylength::Integer, job_priority::Int)

    derivedkeylength > 0 || throw(ArgumentError("Must be > 0."))

    buffer = FastScrypt.pbkdf2_sha256_1(key, salt, FastScrypt.bufferlength(parameters))
    parallelbuffer = unsafe_wrap(Array{UInt32,3}, Ptr{UInt32}(pointer(buffer)), (16, FastScrypt.elementblockcount(parameters), parameters.p));

    jobs = Job[]
    for i ∈ 1:parameters.p
        job = Job(; priority = job_priority) do 
            workingbuffer = Matrix{UInt32}(undef, (16, FastScrypt.elementblockcount(parameters)))
            shufflebuffer = Matrix{UInt32}(undef, (16, FastScrypt.elementblockcount(parameters)))
            scryptblock = Array{UInt32,3}(undef, 16, 2*parameters.r, parameters.N);

            element = @view(parallelbuffer[:, :, i])
            FastScrypt.smix!(scryptblock, workingbuffer, shufflebuffer, element, parameters)
        end
        submit!(job)
        push!(jobs, job)
    end

    for j in jobs
        wait(j)
    end

    derivedkey = FastScrypt.pbkdf2_sha256_1(key, buffer, derivedkeylength)
end 

function FastScrypt.scrypt_threaded(parameters::ScryptParameters, key::Vector{UInt8}, derivedkeylength::Integer, job_priority::Int)
    scrypt_threaded(parameters, key, EMPTY_SALT, derivedkeylength, job_priority)
end

# @setup_workload begin
#     # Putting some things in `@setup_workload` instead of `@compile_workload` can reduce the size of the
#     # precompile file and potentially make loading faster.
#     using FastScrypt
#     using JobSchedulers
#     @compile_workload begin
#         # all calls in this block will be precompiled, regardless of whether
#         # they belong to your package or not (on Julia 1.8 and higher)
#         scrypt_threaded(ScryptParameters(1, 16, 1), Vector{UInt8}(b""), Vector{UInt8}(b""), 64, 0)
#         scrypt_threaded(ScryptParameters(2, 32, 2), Vector{UInt8}(b"password"), Vector{UInt8}(b"NaCl"), 64, 0)
#     end
# end

end