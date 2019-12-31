#
# Implementation of getifaddrs() for Julia.
#
# getifaddrs()
#   Returns a vector of network interface addresses.
#
# inet_flag_names(flags::UInt32)
#   Return a vector of strings with flag names.
#
# inet_netmask_bits(netmask::Union{UInt23,UInt128})
#   Calculates the number of 1 bits in the netmask.
#
# inet_ntop(addr::Union{UInt23,UInt128})
#   Converts the integer form of the network address to a string.
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

if Sys.iswindows()
    error("The 'Getifaddrs' module only works on Linux and MacOS.")
end

#
# Type and function exports.
#
export InterfaceAddress, getifaddrs, inet_flag_names, inet_netmask_bits, inet_ntop

#
# Constant exports.
#
export AF_INET, AF_INET6,
    IFF_UP, IFF_BROADCAST, IFF_DEBUG, IFF_LOOPBACK,
    IFF_POINTOPOINT, IFF_NOTRAILERS, IFF_RUNNING, IFF_NOARP,
    IFF_PROMISC, IFF_ALLMULTI, IFF_MASTER, IFF_SLAVE,
    IFF_MULTICAST, IFF_PORTSEL, IFF_AUTOMEDIA, IFF_DYNAMIC

const AF_INET          = 2
const AF_INET6         = Sys.islinux() ? 10 : Sys.isapple() ? 30 : 23
const INET_ADDRSTRLEN  = 16
const INET6_ADDRSTRLEN = 46

#
# List of interface flags. Taken from /usr/include/net/if.h on Linux.
# The value is the exponent for a power of 2.
#
const IFF_UP          = 0  # Interface is up.
const IFF_BROADCAST   = 1  # Broadcast address valid.
const IFF_DEBUG       = 2  # Turn on debugging.
const IFF_LOOPBACK    = 3  # Is a loopback net.
const IFF_POINTOPOINT = 4  # Interface is point-to-point link.
const IFF_NOTRAILERS  = 5  # Avoid use of trailers.
const IFF_RUNNING     = 6  # Resources allocated.
const IFF_NOARP       = 7  # No address resolution protocol.
const IFF_PROMISC     = 8  # Receive all packets.
const IFF_ALLMULTI    = 9  # Receive all multicast packets.
const IFF_MASTER      = 10 # Master of a load balancer.
const IFF_SLAVE       = 11 # Slave of a load balancer.
const IFF_MULTICAST   = 12 # Supports multicast.
const IFF_PORTSEL     = 13 # Can set media type.
const IFF_AUTOMEDIA   = 14 # Auto media select active.
const IFF_DYNAMIC     = 15 # Dialup device with changing addresses.

#
# List of interface flag names.
#
const flag_names = [
    "UP",
    "BROADCAST",
    "DEBUG",
    "LOOPBACK",
    "POINTOPOINT",
    "NOTRAILERS",
    "LOWER_UP",    # a.k.a. RUNNING
    "NOARP",
    "PROMISC",
    "ALLMULTI",
    "MASTER",
    "SLAVE",
    "MULTICAST",
    "PORTSEL",
    "AUTOMEDIA",
    "DYNAMIC"
]

##############################################################################
#
# Structures visible externally.
#
##############################################################################

struct InterfaceAddress
    name::String
    family::UInt32
    flags::UInt32
    address::Union{UInt32,UInt128}
    netmask::Union{UInt32,UInt128}

    #
    # A broadcast/p2p address or 'false'.
    #
    bcast_or_p2p::Union{InterfaceAddress,Bool}

    #
    # Value specific to IPV6 addresses.
    #
    scope_id::Int32
end

##############################################################################
#
# Structures used for internal access to the C structs.
#
##############################################################################

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

##############################################################################
#
# Internal functions.
#
##############################################################################

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
            flags = local_ia.flags

            if sa.sa_family == AF_INET
                sin = !Sys.isapple() ?
                    unsafe_load(convert(Ptr{sockaddr_in}, local_ia.address)) :
                    unsafe_load(convert(Ptr{sockaddr_in_apple}, local_ia.address))
                sin_mask = !Sys.isapple() ?
                    unsafe_load(convert(Ptr{sockaddr_in}, local_ia.netmask)) :
                    unsafe_load(convert(Ptr{sockaddr_in_apple}, local_ia.netmask))
                address = sin.sin_addr
                netmask = sin_mask.sin_addr
                if flags & 2^IFF_BROADCAST != 0
                    bcast = unsafe_load(convert(Ptr{sockaddr_in}, local_ia.bduaddr))
                    bcast_or_p2p = InterfaceAddress(flag_names[IFF_BROADCAST+1], family, IFF_BROADCAST,
                                                    bcast.sin_addr, UInt32(0), false, -1)
                elseif flags & 2^IFF_POINTOPOINT != 0
                    bcast = unsafe_load(convert(Ptr{sockaddr_in}, local_ia.bduaddr))
                    bcast_or_p2p = InterfaceAddress(flag_names[IFF_POINTOPOINT+1], family, IFF_POINTOPOINT,
                                                    bcast.sin_addr, UInt32(0), false, -1)
                else
                    bcast_or_p2p = false
                end
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
                if flags & 2^IFF_BROADCAST != 0 && local_ia.bduaddr != Ptr{Cvoid}(0)
                    bcast = unsafe_load(convert(Ptr{sockaddr_in6}, local_ia.bduaddr))
                    bcast_or_p2p = Interface(flag_names[IFF_BROADCAST+1], family, IFF_BROADCAST,
                                             bcast.sin_addr, UInt128(0), false, -1)
                elseif flags & 2^IFF_POINTOPOINT != 0 && local_ia.bduaddr != Ptr{Cvoid}(0)
                    bcast = unsafe_load(convert(Ptr{sockaddr_in6}, local_ia.bduaddr))
                    bcast_or_p2p = Interface(flag_names[IFF_POINTOPOINT+1], family, IFF_POINTOPOINT,
                                             bcast.sin_addr, UInt128(0), false, -1)
                else
                    bcast_or_p2p = false
                end
                scope_id = sin6.sin_scope_id
            end
            push!(iflist, InterfaceAddress(name, family, flags, address, netmask, bcast_or_p2p, scope_id))
        end
        if local_ia.next == Ptr{ifaddrs}(0)
            break
        end
        local_ia = unsafe_load(local_ia.next)
    end
    iflist
end

##############################################################################
#
# Functions visible externally.
#
##############################################################################

function inet_flag_names(flags::UInt32)
    names::Vector{String} = []
    for i in 1:16
        if flags & 2^(i-1) != 0
            push!(names, flag_names[i])
        end
    end
    names
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
        ccall(:inet_ntop, Cstring, (UInt32, Ptr{UInt32}, String, UInt32), family, addr_ref, String(buf), size) :
        ccall(:inet_ntop, Cstring, (UInt32, Ptr{UInt128}, String, UInt32), family, addr_ref, String(buf), size)
    if p !== nothing
        p = unsafe_string(p)
    end
    p
end

function getifaddrs()
    iflist = nothing
    ifa_ptr = Ref{Ptr{ifaddrs}}(C_NULL)
    if (n = ccall(:getifaddrs, Cint, (Ptr{Ptr{ifaddrs}},), ifa_ptr)) == 0
        iflist = iterate(ifa_ptr[])
        ccall(:freeifaddrs, Cvoid, (Ptr{ifaddrs},), ifa_ptr[])
    end
    iflist
end

end
