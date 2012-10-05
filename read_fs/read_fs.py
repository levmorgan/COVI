import struct, re
from collections import defaultdict


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
            faces[i] = struct.unpack(">3f", file_str[index:index+12])

        return (comment, vert_count, face_count, verts, faces)

    except struct.error:
        raise ValueError("Invalid data was found in the triangle file.")

    except IndexError:
        raise ValueError("The triangle file is truncated or missing data.")
            
            

        

def parse_annot_file(file_str):
    """
    Parse a string containing a FreeSurfer annot file and return its contents.
    
    Returns:
    (
        labels: a map keyed on each region's label containing lists of vertices
        tab_file: the name of the file that the color table came from
        color_table: a map keyed on the brain area's name, with a list
            of color values


    """
    try:
        num_nodes = struct.unpack('>I', file_str[:4])
        num_nodes = num_nodes[0]

        labels = defaultdict(list)

        file_str = file_str[4:]

        for i in xrange(num_nodes):
            dat = struct.unpack('>II', file_str[i*8:i*8+8])
            labels[dat[1]].append(dat[0])

        offset = 8*num_nodes
        has_table, = struct.unpack('>I', file_str[offset:offset+4])
        if not has_table:
            return labels, None, None

        # Read in the file name for the color table
        offset += 4
        num_entries, tab_file_len,  = struct.unpack('>2I', file_str[offset:offset+8])
        offset += 8
        tab_file, = struct.unpack('>%isx'%(tab_file_len-1), file_str[offset:offset+tab_file_len])

        offset += tab_file_len
        color_table = {}

        if num_entries > 0:
            # Read in the color table data
            for i in xrange(num_entries):
                # Read in the length of the brain area name
                str_len, = struct.unpack('>I', file_str[offset:offset+4])
                offset += 4
                # Read in the name and the 4 integers of color values
                tab_row = struct.unpack('>%isx4I'%(str_len-1), file_str[offset:offset+str_len+16])
                # color_table["brain area name] = [int R, int G, int B, int A(?)]
                color_table[tab_row[0]] = list(tab_row[1:])
                offset += str_len+16
        else:
            raise ValueError("Fewer than 0 entries in the color table! We can't handle that yet!")

            
        return labels, tab_file, color_table

    except struct.error:
        raise ValueError("Invalid data was encountered in the aparc file.")

    except IndexError:
        raise ValueError("The aparc file is truncated or missing data.")
