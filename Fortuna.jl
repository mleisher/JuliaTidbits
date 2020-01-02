#
# A module with my first attempt at implementing the Fergusen and
# Schneier (https://en.wikipedia.org/wiki/Fortuna_(PRNG)) Fortuna
# cryptographically secure random number generator.
#
# This was modeled after Jochen Voss's Fortuna implementation in Go
# (https://github.com/seehuhn/fortuna), and only implements the
# generator, not the entropy accumulator and seed file that go with a
# complete implementation.
#
# No attempt was made to integrate the FortunaRNG with Julia's
# existing RNG infrastructure because I don't understand it. Yet.
#
# Mark Leisher <mleisher@cs.nmsu.edu>
# 31 December 2019
#

#
# Copyright (C) 2020 Mark Leisher <mleisher@cs.nmsu.edu>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
module Fortuna

export FortunaRNG, seed!, reset!, pseudo_random_data!, getrand

#
# Short documentation:
#
# This RNG uses the sha256 hasher and AES256 cipher from Nettle.jl for
# instances that don't specify a hasher and cipher.
#
# FortunaRNG
#
#   There are four different constructors available, two with seeds,
#   two without (near end of this file). If a form without a seed is
#   used, and a seed is not manually set before the first use, an ad
#   hoc seed based on system info is collected and added
#   automatically.
#
# reset!(r::FortunaRNG)
#
#    This resets the hash and cipher used for the RNG.
#
# seed!(r::FortunaRNG, seed::Vector{UInt8})
# seed!(r::FortunaRNG, seed)
#
#    The seed!() functions are for seeding the RNG. The second form
#    simply writes the seed to an IOBuffer, assuming the type can be
#    written to a byte stream.
#
# pseudo_random_data!(r::FortunaRNG, n::Integer) -> Vector{UInt8}
#
#    This function returns 'n' bytes of pseudo-random data.
#
# getrand(r::FortunaRNG, t::Type, count::Integer = 1) -> Vector{t}
#
#    This function generates 'count' items of type 't'.
#
# getrand(r::FortunaRNG, range::AbstractRange, count::Integer = 1) -> Vector{typeof(range[1])}
#
#    This function generates 'count' items that have the same type as
#    the beginning of the range. All of the values are taken from the
#    specified range.
#
# getrand(frng::FortunaRNG, v::AbstractVector, count::Integer = 1) -> Vector{Any}
#
#    This function returns a vector containing randomly selected elements in the source vector.
#
# getrand(frng::FortunaRNG, d::AbstractDict, count::Integer = 1) -> Vector{Pair{Any,Any}}
#
#    This function returns a vector of key/value pairs chosen from the dictionary.
#
# getrand(frng::FortunaRNG, s::AbstractSet, count::Integer = 1) -> Vector{Any}
#
#    This function returns a vector of set members.
#


using Random
using Nettle
#
# Try to load modules found in
# https://github.com/mleisher/JuliaTidbits for ad hoc seeding.
#
try
    using NetworkInterfaces
catch
end
try
    using Getpwnam
catch
end

const maxBlocks = UInt64(1 << 16)

mutable struct FortunaRNG <: AbstractRNG
    hasher::Hasher
    key::Vector{UInt8}
    cipher::Encryptor
    counter::Vector{UInt8}
    hash_key_size::UInt32
    cipher_block_size::UInt32
end

function set_key!(frng::FortunaRNG, key::Vector{UInt8})
    if length(key) != frng.hash_key_size
        error("set_key!: wrong key length.")
    end

    frng.key = key

    #
    # Generate a new cipher of the same type. This needs to be done
    # because Nettle.jl doesn't offer a function that calls
    # set_encrypt_key() to reset the cipher.
    #
    frng.cipher = Encryptor(frng.cipher.cipher_type.name, frng.key)
    frng.cipher_block_size = frng.cipher.cipher_type.block_size
end

#
# Increment the counter. Manually manage overflow because it is an
# error to overflow a UInt8 in a vector of them. This could probably
# be a UInt128, but it is left this way in case larger cipher block
# sizes come along in the future.
#
function inc!(frng::FortunaRNG)
    for i in 1:length(frng.counter)
        if frng.counter[i] == 255
            frng.counter[i] = 0
        else
            frng.counter[i] += 1
        end
        if frng.counter[i] > 0 break end
    end
end

#
# Ad hoc entropy sources to seed the RNG.
#
function ad_hoc_seed!(frng::FortunaRNG)
    b = IOBuffer()

    #
    # 1. Add random bytes the length of the hash key using the builtin
    #    random number generator.
    #
    write(b, rand(UInt8, frng.hash_key_size))

    #
    # 2. Add OS-specific "random" stuff.
    #
    enough = 0
    if Sys.islinux()
        for i in ["/proc/timer_list", "/proc/stat"]
            #
            # Only open the file if it has read permissions for this user.
            #
            if stat(i).mode & 4 != 0
                open(i) do file
                    for ln in eachline(file) enough += write(b, ln) end
                end
            end
        end
    end
    #
    # If reading OS-specific files didn't provide at least 2KiB, get
    # the rest from the system's random device.
    #
    if enough < 2048
        rd = RandomDevice()
        write(b, rand(rd, UInt8, 2048 - enough))
    end

    #
    # 3. Add the current time.
    #
    write(b, reinterpret(UInt64, time()))

    #
    # 4. Add network interfaces if the
    #    https://github.com/mleisher/JuliaTidbits modules are available.
    #
    try
        for nic in NICList()
            write(b, nic.name, nic.mac, nic.flags, nic.mtu)
        end
    catch
        #
        # NICList() isn't available.
        #
    end

    #
    # 5. Add current user info if the
    #    https://github.com/mleisher/JuliaTidbits modules are available.
    #
    try
        u = getpwnam(ENV[Sys.iswindows() ? "USERNAME" : "USER"])
        write(b, u.name, u.uid, u.gid, u.gecos, u.dir, u.shell)
    catch
        #
        # getpwnam() isn't available.
        #
    end

    #
    # 6. Add the Julia process ID.
    #
    write(b, UInt64(getpid()))

    #
    # 7. Reseed!
    #
    seed!(frng, take!(b))
end

#
# This can probably be inlined. It checks to see if the counter is all
# zeros or not. Assumes the counter vector exists.
#
function is_zero(b::Vector{UInt8})
    b[1] == 0 && all(==(first(b)),b)
end

#
# Generate blocks and store them in the supplied byte vector.
#
function generate_blocks!(frng::FortunaRNG, buf::Vector{UInt8}, count::UInt64)
    if is_zero(frng.counter)
        ad_hoc_seed!(frng)
    end
    res = zeros(UInt8, frng.cipher_block_size)
    for i in 1:count
        encrypt!(frng.cipher, res, frng.counter)
        append!(buf, res)
        inc!(frng)
    end
end

#
# Generate the blocks and return them as a byte vector.
#
function generate_blocks(frng::FortunaRNG, count::UInt64)
    if is_zero(frng.counter)
        ad_hoc_seed!(frng)
    end
    buf::Vector{UInt8} = []
    res = zeros(UInt8, frng.cipher_block_size)
    for i in 1:count
        encrypt!(frng.cipher, res, frng.counter)
        append!(buf, res)
        inc!(frng)
    end
    buf
end

######################################################################
#
# Publicly visible API.
#
######################################################################


#
# Reset the RNG.
#
function reset!(frng::FortunaRNG)
    fill!(frng.counter, zero(length(frng.counter)))
    set_key!(frng, zeros(UInt8, frng.hash_key_size))
end

function seed!(frng::FortunaRNG, seed::Vector{UInt8})
    #
    # Reset the hasher and update it. In libnettle (backend for
    # Nettle.jl), getting the digest resets the hasher.
    #
    digest!(frng.hasher)
    update!(frng.hasher, frng.key)
    update!(frng.hasher, seed)

    #
    # Do a double hash.
    #
    second_hasher = Hasher(frng.hasher.hash_type.name)
    update!(second_hasher, digest!(frng.hasher))
    set_key!(frng, digest!(second_hasher))
    inc!(frng)
end

function seed!(frng::FortunaRNG, v)
    b = IOBuffer()
    if length(v) > 0
        write(b, v)
    end
    seed!(frng, take!(b))
end

#
# Generate 'n' bytes of pseudo-random data and return them.
#
function pseudo_random_data!(frng::FortunaRNG, n::Integer)
    n = abs(n)
    nblocks  = convert(UInt64, floor((n + frng.cipher_block_size - 1) / frng.cipher_block_size))
    nkblocks = convert(UInt64, floor((frng.hash_key_size + frng.cipher_block_size - 1) / frng.cipher_block_size))

    #
    # Storage for random data.
    #
    res::Vector{UInt8} = []

    while nblocks > 0
        c = min(nblocks, maxBlocks)
        generate_blocks!(frng, res, c)
        nblocks -= c

        nkey = generate_blocks(frng, nkblocks)
        set_key!(frng, nkey[1:frng.hash_key_size])
    end
    res[1:n]
end

function getrand(frng::FortunaRNG, d::AbstractDict, count::Integer = 1)
    count = abs(count)
    out::Vector{Pair{Any,Any}} = []

    if length(d) > 0
        #
        # Get an indexable array of keys.
        #
        k = collect(keys(d))
        for idx in getrand(frng, 1:length(d), count)
            push!(out, Pair(k[idx], d[k[idx]]))
        end
    end
    out
end

function getrand(frng::FortunaRNG, s::AbstractSet, count::Integer = 1)
    count = abs(count)
    out::Vector{Any} = []

    if length(s) > 0
        #
        # Collect all the set members into an indexable vector.
        #
        sm = collect(s)
        for idx in getrand(frng, 1:length(s), count)
            push!(out, sm[idx])
        end
    end
    out
end

function getrand(frng::FortunaRNG, v::AbstractVector, count::Integer = 1)
    count = abs(count)
    out::Vector{Any} = []

    if length(v) > 0
        for idx in getrand(frng, 1::length(v), count)
            push!(out, v[idx])
        end
    end
    out
end

function getrand(frng::FortunaRNG, range::AbstractRange, count::Integer = 1)
    t = typeof(range[1])

    #
    # Guard against non-bits types.
    #
    if !isbitstype(t)
        return []
    end

    count = abs(count)
    out::Vector{t} = []
    for i in 1:count
        idx = reinterpret(UInt128, pseudo_random_data!(frng, sizeof(UInt128)))
        idx = convert(UInt128, floor(idx[1]/typemax(UInt128)*length(range)+1))
        append!(out, range[idx])
    end
    out
end

function getrand(frng::FortunaRNG, t::Type, count::Integer = 1)
    #
    # Guard against non-bits types.
    #
    if !isbitstype(t)
        return []
    end

    count = abs(count)
    a = reinterpret(t, pseudo_random_data!(frng, sizeof(t) * count))
    Vector{t}(a)
end

#
# Most useful constructors.
#

#
# The first two constructors do not seed the generator.
#
# If these two are used WITHOUT manually seeding first, an ad hoc seed
# is added automatically. If a specific seed is wanted later, call
# reset!() on the RNG before seeding with the desired value. Example:
#
# r = FortunaRNG()
# v = getrand(r, Char, 10)
# map(x -> println(x), v)
# reset!(r)
# seed!(r, 0x1020304)
#
function FortunaRNG()
    h = Hasher("sha256")
    frng = FortunaRNG(h, Encryptor("AES256", zeros(UInt8, h.hash_type.digest_size)))
    frng
end

function FortunaRNG(h::Hasher, e::Encryptor)
    frng = FortunaRNG(h, zeros(UInt8, h.hash_type.digest_size),
                      e, zeros(UInt8, e.cipher_type.block_size),
                      h.hash_type.digest_size,
                      e.cipher_type.block_size)
    frng
end

function FortunaRNG(seed)
    h = Hasher("sha256")
    frng = FortunaRNG(h, Encryptor("AES256", zeros(UInt8, h.hash_type.digest_size)), seed)
    frng
end

function FortunaRNG(h::Hasher, e::Encryptor, seed)
    frng = FortunaRNG(h, zeros(UInt8, h.hash_type.digest_size),
                      e, zeros(UInt8, e.cipher_type.block_size),
                      h.hash_type.digest_size,
                      e.cipher_type.block_size)
    seed!(frng, seed)
    frng
end

import Base.show
function show(io::IO, frng::FortunaRNG)
    write(io, "\nhasher = ")
    show(io, frng.hasher)
    write(io, "\nkey = ")
    show(io, frng.key)
    write(io, "\ncipher = ")
    show(io, frng.cipher)
    write(io, "\ncounter = ")
    show(io, frng.counter)
    write(io, "\nhash_key_size = ")
    show(io, frng.hash_key_size)
    write(io, "\ncipher_block_size = ")
    show(io, frng.cipher_block_size)
end

end
