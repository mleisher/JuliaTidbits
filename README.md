# JuliaTidbits
Random Julia code/modules that might be useful to someone.

Getpwnam.jl
Implements getpwnam() for Julia and uses a kludgy method of getting similar info from Windows. 

NetworkInterfaces.jl
Gets a list of network interfaces (ignoring the loopback) from the device. Kludgy approach to getting this info from Mac OS and Windows, but it works well enough for one of my personal projects.

hrbc.jl
Print byte counts in "human readable" form. Based on code found at https://programming.guide/java/formatting-byte-size-to-human-readable-format.html.
