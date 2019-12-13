#!/usr/bin/julia

#
# Print bytes in 'human readable' units.
#
# Julia adaptation of Java code developed by Andreas Lundblad and published at:
#
#   https://programming.guide/java/formatting-byte-size-to-human-readable-format.html
#
# Mark Leisher <mleisher@cs.nmsu.edu>
# 04 December 2019
#

using Printf

#
# Unit strings and denominators for binary division.
#
units   = ["K",  "M",  "G",  "T",  "P"]
bin_div = [0x1p10, 0x1p20, 0x1p30, 0x1p40, 0x1p40]

function humanReadableByteCountSI(bytes::Int64)
    neg = bytes < 0 ? "-" : ""
    b = bytes == typemin(Int64) ? typemax(Int64) : abs(bytes)
    if b < 1000
        return @sprintf("%s%d B", neg, b)
    end
    for i in 1:5
        if b < 999950
            return @sprintf("%s%.1f %sB", neg, b / 1e3, units[i])
        end
        b /= 1000
    end
    return @sprintf("%s%.1f EB", neg, b / 1e3)
end

function humanReadableByteCountBin(bytes::Int64)
    b = bytes == typemin(Int64) ? typemax(Int64) : abs(bytes)
    if b < 1024
        return @sprintf("%d B", b)
    end
    sf = 40
    for i in 1:5
        if b < 0xfffcccccccccccc >> sf
            if i == 5
                b >>= 10
            end
            return @sprintf("%.1f %siB", b / bin_div[i], units[i])
        end
        sf -= 10
    end
    b = (b >> 20) / 0x1p40
    return @sprintf("%.1f EiB", b)
end

testing = true
if testing
    @printf("SI Units\n%s\n", "-"^8)
    @printf("%s\n", humanReadableByteCountSI(0))
    @printf("%s\n", humanReadableByteCountSI(27))
    @printf("%s\n", humanReadableByteCountSI(999))
    @printf("%s\n", humanReadableByteCountSI(1000))
    @printf("%s\n", humanReadableByteCountSI(1023))
    @printf("%s\n", humanReadableByteCountSI(1024))
    @printf("%s\n", humanReadableByteCountSI(1728))
    @printf("%s\n", humanReadableByteCountSI(1855425871872))
    @printf("%s\n", humanReadableByteCountSI(typemax(Int64)))

    @printf("\nBinary Units\n%s\n", "-"^12)
    @printf("%s\n", humanReadableByteCountBin(0))
    @printf("%s\n", humanReadableByteCountBin(27))
    @printf("%s\n", humanReadableByteCountBin(999))
    @printf("%s\n", humanReadableByteCountBin(1000))
    @printf("%s\n", humanReadableByteCountBin(1023))
    @printf("%s\n", humanReadableByteCountBin(1024))
    @printf("%s\n", humanReadableByteCountBin(1728))
    @printf("%s\n", humanReadableByteCountBin(1855425871872))
    @printf("%s\n", humanReadableByteCountBin(typemax(Int64)))
end
