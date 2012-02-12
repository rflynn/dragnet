# Dragnet

## Install
    $ git clone git://github.com/rflynn/dragnet.git
    $ cd dragnet/src
    $ make

## Examples
    # watch google load in slow-mo via wget's blocking sockets
    $ LD_PRELOAD=./dragnet.so wget http://www.google.com/ -O - 2>/dev/null

    # watch google load in slow-mo via curl's non-blocking sockets
    $ LD_PRELOAD=./dragnet.so curl http://www.google.com/ -o - 2>/dev/null

    # watch dragnet at work
    $ LD_PRELOAD=./dragnet.so wget http://www.google.com/ -O - >/dev/null

## What?
dragnet is a straight-forward UNIX utility to simulate network problems.

## Why?
Only when network problems exist are problems in networked applications fixed.

## How?
dragnet uses LD_PRELOAD to intercept libc networking function calls like socket(), send(), recv() and close() and wrap these calls with its own buffering to simulate a slow network.


## Where?
http://github.com/rflynn/dragnet

## Who?
Ryan Flynn parseerror+dragnet@gmail.com

