#
# Simple module to collect a list of network interfaces from the
# machine.
#
# Example:
#   using NetworkInterfaces
#   for i in NICList()
#       @show(i)
#    end
#
# Mark Leisher <mleisher@cs.nmsu.edu>
# 13 December 2019
#

module NetworkInterfaces

export NIC, NICList

struct NIC
    name::String
    mac::String
    flags::UInt32
    mtu::UInt32
end

if Sys.islinux()
    #
    # Location of NIC info on many Linux dists.
    #
    linux_sys_class_net = "/sys/class/net"
end

function NICList()
    interfaces::Vector{NIC} = []
    if Sys.islinux()
        #
        # Get the list of interfaces and filter out the loopback
        # interface.
        #
        for ifname in filter(x -> x != "lo", cd(readdir, linux_sys_class_net))
            ifmac = strip(read(string(linux_sys_class_net,"/",ifname,"/address"), String), ['\r', '\n'])
            ifflags = parse(UInt32, read(string(linux_sys_class_net,"/",ifname,"/flags"), String))
            ifmtu = parse(UInt32, read(string(linux_sys_class_net,"/",ifname,"/mtu"), String))
            push!(interfaces, NIC(ifname, ifmac, ifflags, ifmtu))
        end
    elseif Sys.isapple()
        open(`/sbin/ifconfig`, "r") do file
            ifname  = ""
            ifaddr  = ""
            ifflags = 0
            ifmtu   = 0
            for ln in eachline(file)
                if (m = match(r"([a-z0-9]+): flags=(\d+)<[^>]+> mtu (\d+)", ln)) !== nothing
                    ifname = m[1]
                    ifflags = parse(UInt32, m[2])
                    ifmtu = parse(UInt32, m[3])
                elseif (m = match(r"ether ([0-9a-f:]+)", ln)) !== nothing
                    ifaddr = m[1]
                    push!(interfaces, NIC(ifname, ifaddr, ifflags, ifmtu))
                end
            end
        end
    elseif Sys.iswindows()
        #
        # Hash table to track interfaces and their MTU values.
        #
        mtumap = Dict{String, UInt32}()

        #
        # First, get the MTU for each interface.
        #
        open(`netsh interface ipv4 show subinterfaces`, "r") do file
            for ln in eachline(file)
                if match(r"^\s*\d+", ln) == nothing
                    continue
                end
                fields = split(strip(ln), r"\s+")
                ifmtu = parse(UInt32, fields[1])
                #
                # Ignore elements 2-4 and collect the rest into the
                # interface name.
                #
                ifname = join(fields[5:length(fields)], " ")
                mtumap[ifname] = ifmtu
            end
        end

        #
        # Next, get the interfaces.
        #
        # IMPORTANT: wmic sorts the output fields alphabetically, so
        # the MAC address will always appear before the connection id
        # no matter which order they are specified on the command
        # line.
        #
        open(`wmic nic get MACAddress, NetConnectionID`, "r") do file
            ifname  = ""
            ifaddr  = ""
            ifflags = 0
            ifmtu   = 0
            for ln in eachline(file)
                if (m = match(r"^([0-9A-F:]+)\s+([^\s]+)", ln)) !== nothing
                    ifname = m[2]
                    ifaddr = lowercase(m[1])
                    if (ifmtu = get(mtumap, ifname, nothing)) === nothing
                        ifmtu = 0
                    end
                    push!(interfaces, NIC(ifname, ifaddr, ifflags, ifmtu))
                end
            end
        end
    end
    interfaces
end

end
