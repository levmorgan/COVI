import struct, sys, json
from os import stat

infi = open(sys.argv[1], 'rb')

num_nodes = 0
data = []

num_nodes = struct.unpack('>I', infi.read(4))
num_nodes = num_nodes[0]
print "num_nodes: %i"%(num_nodes)
raw_input()

labels = {}

for i in xrange(num_nodes):
    raw_dat = infi.read(8)
    if len(raw_dat) == 8:
        dat = struct.unpack('>II', raw_dat)
        if not dat[1] in labels:
            labels[dat[1]] = [dat[0]]
        else:
            labels[dat[1]].append(dat[0])

out = open("labels", "w")
out.write(json.dumps(labels, sort_keys=True, indent=4))
out.close()
