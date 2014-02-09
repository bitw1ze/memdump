# memdump

## What

Dump the memory of a process. Memdump should work on x86, x86_64, ARM, and
probably other 32-bit and 64-bit architectures, as long as it's running on a
unixy system that supports the PTRACE API.

# Why

It's nice sometimes just to be able to see what's in the memory of a process
and grep for interesting things without having to spin up GDB or do any other
crazy stuff. I haven't seen another a tool that dumps memory the way I want, so
I made one. Also I was bored and felt like learning the ptrace API, so I
figured this would be a nice tool to write.

## How

<pre>
$ cc main.c memdump.c -o memdump
$ ./memdump -h
Usage: ./memdump &lt;segment(s)&gt; [opts] -p &lt;pid&gt;

Options:
   -A              dump all segments
   -D              dump data segments
   -S              dump the stack
   -H              dump the heap
   -d &lt;dir&gt;        save dumps to custom directory
   -p &lt;pid&gt;        pid of the process to dump
   -v              verbose
   -h              this menu
$ sudo ./memdump -d output -S -H -p $(pgrep some_app)
...
$ strings -f output/*.dump | grep your_password
output/7668d000-7668f000.dump: your_password
</pre>

## What about Android?

You need the Android NDK with your platform's gcc binary in your PATH. Change
architecture as needed. This may not work on all devices and OS versions, but
it worked for me on Android 4.4 on an emulated and a real Nexus 4. You must run
memdump as root.

<pre>
$ arm-linux-gnueabi-gcc main.c memdump.c -static -march=armv7-a -o memdump
$ adb push memdump /data/local/tmp
$ adb shell
# cd /data/local/tmp
# ps
# ./memdump -d output -D -S -H -p 31337
# ls output
a6895000-a6897000.dump
a6898000-a6995000.dump
a6995000-a699b000.dump
a699c000-a6a99000.dump
a6a99000-a6a9f000.dump
a6aa0000-a6b9d000.dump
a6b9d000-a6ba3000.dump
...
</pre>

# Contribute

Feel free to clean up the code or add a feature in a pull request. Let me know
if you have any questions.

# License

http://www.wtfpl.net/txt/copying/
