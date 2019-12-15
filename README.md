# JuliaTidbits
Random Julia code/modules that might be useful to someone.

<h5>Getifaddrs.jl</h5>
Implements getifaddrs() for Julia. Some of the exports may collide with other modules, if they export AF_INET and or AF_INET6.

<h5>Getpwnam.jl</h5>
Implements getpwnam() for Julia and uses a kludgy method of getting similar info from Windows. 

<h5>NetworkInterfaces.jl</h5>
Gets a list of network interfaces (ignoring the loopback) from the device. Kludgy approach to getting this info from Mac OS and Windows, but it works well enough for one of my personal projects.

<h5>hrbc.jl</h5>
Print byte counts in "human readable" form. Based on code found at https://programming.guide/java/formatting-byte-size-to-human-readable-format.html.
