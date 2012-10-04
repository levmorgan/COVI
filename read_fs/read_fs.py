import struct
import re

def parse_triangle_file(file_str):
    """
    Parse the contents of a string as a triangle file and return a tuple:
    (
        file comment, 
        number of vertices, 
        number of faces, 
        list of 3-tuples of vertex coordinates in RAS format,
        list of 3-tuples of vertex numbers for each polygon
    )
    """
    try:

        # Try to unpack the magic number and comment

        # Assert the magic number is correct
        if struct.unpack('3B', file_str[:3]) != (255, 255, 254):
            raise ValueError("The triangle file's magic number is incorrect. It should be 0xFFFFFE.")

        # Unpack the comment string
        comment = file_str[3:303]
        mat = re.match(".*\n\n", comment)
        if not mat:
            raise ValueError("The comment in the triangle file"+
                                " is too long or invalid.")

        comment = mat.string[mat.start():mat.end()]
        end = 3+mat.end()

        vert_count, face_count = struct.unpack(">i i", file_str[end:end+8])
        verts = [(0.,0.,0.) for i in xrange(vert_count)]
        file_str = file_str[end+8:]

        if len(file_str)%4 != 0:
            raise ValueError("The triangle file is corrupt. It's length is invalid.")

        for i in xrange(vert_count):
            try:
                verts[i] = struct.unpack(">3f", file_str[12*i:12*i+12])
            except:
                print i
                raw_input()

        faces = [(0.,0.,0.) for i in xrange(face_count)]
        
        for i in xrange(face_count):
            index = 12*i+vert_count
            faces[i] = struct.unpack(">3f", file_str[i:i+12])

        return (comment, vert_count, face_count, verts, faces)

    except struct.error:
        raise ValueError("Invalid data was found in the triangle file.")

    except IndexError:
        raise ValueError("The triangle file is truncated or missing data.")
            
            

        

def parse_aparc_file(file_str):
    num_nodes = struct.unpack('>I', infi.read(4))
    num_nodes = num_nodes[0]

    labels = defaultdict(list)

    for i in xrange(num_nodes):
        ### THIS IS NOT A FILE! IT'S A STRING! THIS IS MADNESS!
        raw_dat = infi.read(8)
        if len(raw_dat) == 8:
            dat = struct.unpack('>II', raw_dat)
            labels[dat[1]].append(dat[0])

    return labels
