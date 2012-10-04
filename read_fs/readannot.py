import struct, sys

infi = open(sys.argv[1], 'rb')

num_nodes = 0
data = []

num_nodes = struct.unpack('>I', infi.read(4))
print "num_nodes: %i"%(num_nodes)

dat = struct.unpack('>II', infi.read(8))
print "\n%i, %i"%dat
inp = raw_input()
while inp != 'q':
    if inp == '':
        last = dat[1]
        count = 0
        while dat[1] == last:
            dat = struct.unpack('>II', infi.read(8))
            count += 1
        print "%ix %i"%(count, last)

    print "%i, %i"%dat

    dat = struct.unpack('>II', infi.read(8))
    inp = raw_input()

