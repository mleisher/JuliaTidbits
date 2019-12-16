#
# Implementation of getifaddrs() for Julia.
#
# getifaddrs()
#   Returns a vector of network interface addresses.
#
# inet_ntop(addr::Union{UInt23,UInt128})
#   Converts the integer form of the network address to a string.
#
# inet_netmask_bits(netmask::Union{UInt23,UInt128})
#   Calculates the number of 1 bits in the netmask.
#
# Example usage:
#
#  using Getifaddrs
#  for interface in getifaddrs()
#      print(interface.name," AF_INET",interface.family == AF_INET6 ? "6 " : " ")
#      println(inet_ntop(interface.address),"/",inet_netmask_bits(interface.netmask))
#  end
#
# Mark Leisher <mleisher@cs.nmsu.edu>
# 15 December 2019
#

module Getifaddrs

export AF_INET, AF_INET6, InterfaceAddress, getifaddrs, inet_ntop, inet_netmask_bits

const AF_INET          = 2
const AF_INET6         = Sys.iswindows() ? 23 : Sys.isapple() ? 30 : 10
const INET_ADDRSTRLEN  = 16
const INET6_ADDRSTRLEN = 46

struct InterfaceAddress
    name::String
    family::UInt32
    address::Union{UInt32,UInt128}
    netmask::Union{UInt32,UInt128}

    #
    # Value specific to IPV6 addresses.
    #
    scope_id::Int32
end

#
# Structure to use with a call to the C/C++ getifaddrs() function.
#
struct ifaddrs
    next::Ptr{ifaddrs}
    name::Ptr{UInt8}
    flags::Cuint
    address::Ptr{Cvoid}
    netmask::Ptr{Cvoid}
    #
    # Broadcast or destination address. Union.
    #
    bduaddr::Ptr{Cvoid}
    data::Ptr{Cvoid}
end

struct sockaddr_apple
    sa_size::UInt8
    sa_family::UInt8
    sa_data::Ptr{Cvoid}
end

struct sockaddr_in_apple
    sin_size::UInt8
    sin_family::UInt8
    sin_port::UInt16
    sin_addr::UInt32
    pad::Ptr{Cvoid}
end

struct sockaddr_in6_apple
    sin_size::UInt8
    sin_family::UInt16
    sin_port::UInt16
    sin_flowinfo::UInt32
    sin_addr::UInt128
    sin_scope_id::UInt32
end

struct sockaddr
    sa_family::UInt16
    sa_data::Ptr{Cvoid}
end

struct sockaddr_in
    sin_family::UInt16
    sin_port::UInt16
    sin_addr::UInt32
    pad::Ptr{Cvoid}
end

struct sockaddr_in6
    sin_family::UInt16
    sin_port::UInt16
    sin_flowinfo::UInt32
    sin_addr::UInt128
    sin_scope_id::UInt32
end

function inet_netmask_bits(netmask::Union{UInt32,UInt128})
    nbits = typeof(netmask) == UInt32 ? 32 : 128
    count = 0
    for i in 1:nbits
        if netmask & 2^(i-1) != 0
            count = count + 1
        end
    end
    count
end

function inet_ntop(addr::Union{UInt32,UInt128})
    if typeof(addr) == UInt32
        family = AF_INET
        size = INET_ADDRSTRLEN
        addr_ref = Ref{UInt32}(addr)
    else
        family = AF_INET6
        size = INET6_ADDRSTRLEN
        addr_ref = Ref{UInt128}(addr)
    end
    buf = zeros(UInt8, size)
    p = typeof(addr) == UInt32 ?
        ccall(:inet_ntop, Cstring, (UInt32, Ptr{UInt32}, String, UInt32),
              family, addr_ref, String(buf), size) :
                  ccall(:inet_ntop, Cstring, (UInt32, Ptr{UInt128}, String, UInt32),
                        family, addr_ref, String(buf), size)
    if p !== nothing
        p = unsafe_string(p)
    end
    p
end

function iterate(ia::Ptr{ifaddrs})
    iflist::Vector{InterfaceAddress} = []

    local_ia = unsafe_load(ia)
    while true
        sa = !Sys.isapple() ?
            unsafe_load(convert(Ptr{sockaddr},local_ia.address)) :
            unsafe_load(convert(Ptr{sockaddr_apple},local_ia.address))

        family = sa.sa_family
        if family == AF_INET || family == AF_INET6
            name = unsafe_string(local_ia.name)
            if sa.sa_family == AF_INET
                sin = !Sys.isapple() ?
                    unsafe_load(convert(Ptr{sockaddr_in}, local_ia.address)) :
                    unsafe_load(convert(Ptr{sockaddr_in_apple}, local_ia.address))
                sin_mask = !Sys.isapple() ?
                    unsafe_load(convert(Ptr{sockaddr_in}, local_ia.netmask)) :
                    unsafe_load(convert(Ptr{sockaddr_in_apple}, local_ia.netmask))
                address = sin.sin_addr
                netmask = sin_mask.sin_addr
                scope_id = -1
            else
                sin6 = !Sys.isapple() ?
                    unsafe_load(convert(Ptr{sockaddr_in6}, local_ia.address)) :
                    unsafe_load(convert(Ptr{sockaddr_in6_apple}, local_ia.address))
                sin6_mask = !Sys.isapple() ?
                    unsafe_load(convert(Ptr{sockaddr_in6}, local_ia.netmask)) :
                    unsafe_load(convert(Ptr{sockaddr_in6_apple}, local_ia.netmask))
                address = sin6.sin_addr
                netmask = sin6_mask.sin_addr
                scope_id = sin6.sin_scope_id
            end
            push!(iflist, InterfaceAddress(name, family, address, netmask, scope_id))
        end
        if local_ia.next == Ptr{ifaddrs}(0)
            break
        end
        local_ia = unsafe_load(local_ia.next)
    end
    iflist
end

function getifaddrs()
    ifa_ptr = Ref{Ptr{ifaddrs}}(C_NULL)
    if (n = ccall(:getifaddrs, Cint, (Ptr{Ptr{ifaddrs}},), ifa_ptr)) == 0
        iflist = iterate(ifa_ptr[])
        ccall(:freeifaddrs, Cvoid, (Ptr{ifaddrs},), ifa_ptr[])
    end
    iflist
end

end
