#
# Simple module to call the getpwnam() function from libc and
# return the results.
#
# Example:
#   using Getpwnam
#   uservar = Sys.iswindows() ? "USERNAME" : "USER"
#   p = getpwnam(ENV[uservar])
#   @show(p)
#
# Mark Leisher <mleisher@cs.nmsu.edu>
# 06 December 2019
#
# Updates:
#
# 13 December 2019
# ----------------
#   Added kludgy support for Windows and a nicely formatted output
#   function just for show.
#

module Getpwnam

export getpwnam, Passwd

#
# Exported.
#
abstract type Passwd end

#
# Password structure for Linux, Unix, and Mac OS.
#
struct PasswdOther <: Passwd
    name::String
    pswd::String
    uid::UInt32
    gid::UInt32
    gecos::String
    dir::String
    shell::String
end

#
# Password structure for Windows.
#
struct PasswdWin <: Passwd
    name::String
    pswd::String
    uid::String
    gid::Vector{String}
    gecos::String
    dir::String
    shell::String
end

#
# Internal structure that gets converted to PasswdOther before being
# passed back from getpwnam().
#
struct passwd
    name::Ptr{UInt8}
    pswd::Ptr{UInt8}
    uid::Cuint
    gid::Cuint
    gecos::Ptr{UInt8}
    dir::Ptr{UInt8}
    shell::Ptr{UInt8}
end

#
# Function to get the list of local user groups for a user on Windows.
#
function win_getlocalgroups(name::AbstractString)
    groups = [""]
    if Sys.iswindows()
        open(`net user $(name)`) do file
            for ln in eachline(file)
                if (m = match(r"^Local Group Memberships\s+(.*)$", ln)) !== nothing
                    groups = map(g -> strip(g), split(m[1], r"\s*\*"))
                    groups = groups[2:length(groups)]
                    break
                end
            end
        end
    end
    groups
end

#
# Function to call Linux, Unix, or Mac OS function getpwnam(), or
# collect similar info from various command line programs on Windows.
#
# Exported.
#
function getpwnam(name::AbstractString)
    if !Sys.iswindows()
        pptr = ccall(:getpwnam, Ptr{Ptr{Cvoid}}, (Cstring,), name)
        if pptr == C_NULL
            return nothing
        end
        p = unsafe_load(convert(Ptr{passwd}, pptr))
        #
        # Return the structure.
        #
        name   = p.name  != C_NULL ? unsafe_string(p.name)  : ""
        pswd   = p.pswd  != C_NULL ? unsafe_string(p.pswd)  : ""
        gecos  = p.gecos != C_NULL ? unsafe_string(p.gecos) : ""
        dir    = p.dir   != C_NULL ? unsafe_string(p.dir)   : ""
        shell  = p.shell != C_NULL ? unsafe_string(p.shell) : ""
        pswd = PasswdOther(name, pswd, p.uid, p.gid, gecos, dir, shell)
    else
        open(`wmic useraccount where name="'$(name)'" get fullname,sid`) do file
            for ln in eachline(file)
                if startswith(ln, "FullName")
                    continue
                end
                dir = raw"C:\Users\\"*name
                if !isdir(dir)
                    dir = ""
                end
                parts = split(ln, r"\s+")
                pop!(parts)
                uid = strip(pop!(parts))
                pswd = PasswdWin(name, "x", uid, win_getlocalgroups(name), join(parts, " "),
                                 dir, raw"C:\Windows\system32\cmd.exe")
                break
            end
        end
    end
    pswd
end

#
# Function to display the contents of the structure. Could be changed
# to JSON output later.
#
import Base.show
function show(io::IO, p::Passwd)
    write(io, "\n")
    write(io, "  name  : ", p.name,  "\n")
    write(io, "  pswd  : ", p.pswd,  "\n")
    write(io, "  gecos : ", p.gecos, "\n")
    write(io, "  dir   : ", p.dir,   "\n")
    write(io, "  shell : ", p.shell, "\n")
    write(io, "  uid   : ", typeof(p) != PasswdWin ? string(p.uid) : p.uid,   "\n")
    write(io, "  gid   : ", typeof(p) != PasswdWin ? string(p.gid) : join(p.gid, ","))
end

end
