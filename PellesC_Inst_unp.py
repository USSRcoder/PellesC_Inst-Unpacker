import zlib
import struct
import datetime
import os, sys

print('\nPellesC Install (13.00) Unpacker. 13.05.2025\n')

# signature
#
SIGN = bytes('PellesC_Inst','ansi');

# fielter only opcodes `3`(extract path) and `5`(extract file)
# 
g_filter =[3,5]

#
# agrs
def help():
    print('Usage :',sys.argv[0], 'setup.exe [-x<dir>]')
    print('\t-x<dir> - \teXtract to dir')
    print('\t*Unpack files to current dir.')
    exit();

g_fn = ''
g_extract_dir = ''
g_arg_len = len(sys.argv)-1
i = g_arg_len
while i > 0:
    if (sys.argv[i][0:1]=='-' or sys.argv[i][0:1]=='/'):
        if (sys.argv[i][1:2]=='?' or sys.argv[i][1:2]=='h'):
            help()
        elif sys.argv[i][1:2]=='x':
            g_odir = sys.argv[i][2:].strip()
            if g_odir !='':
                g_extract_dir = g_odir
                if g_extract_dir[:-1] != '\\':
                    g_extract_dir += '\\'

    else:
        g_fn = sys.argv[i]
    i-=1

if (g_fn==''): 
    help()

def get_time(filetime):
    value = datetime.datetime (1601, 1, 1) + datetime.timedelta(seconds= ((getdw(filetime,0) << 32) + getdw(filetime,4)) / 10000000) ### combine str 3 and 4  
    return value.strftime('%Y-%m-%d %H:%M:%S')
def setdw(V, ofs, val):
    x = struct.pack('I', val);    V[ofs + 0] = x[0];    V[ofs + 1] = x[1];    V[ofs + 2] = x[2];    V[ofs + 3] = x[3];
def getdw(V, ofs):
    return ( (V[ofs+3] << 24) |      (V[ofs+2] << 16) |      (V[ofs+1] << 8) |      (V[ofs+0] << 0)     )


#
# check signature
with open(g_fn, "rb") as input_file:
   buff = input_file.read()
   _ofs = buff.find(SIGN) - 8;
if (_ofs < 0):
    print('Error:', ' signature not found.')
    exit();
print("- Signature at:", hex(_ofs))

# load overlay
#
buff = buff[_ofs:]

# script decompress
# 
script_header = getdw(buff, 5 * 4);
script_len = ((getdw(buff, script_header + 0x20) + 4) & 0x7FFFFFFF)
print("- Script: [", hex(script_header),':',hex(script_len),']')
script_compressed = buff[ script_header + 0x24 : script_header + 0x24 + script_len]
input_data = zlib.decompress(script_compressed)

#with open("over.bin_end.unp", "rb") as input_file:
#   input_data = input_file.read()

# parse script
# 
fl_end   = getdw(input_data, 0x54) * 0x14 + 0xAC
fl_begin = 0xAC
fl_data = fl_end + getdw(input_data, 0x58) * 0x18
#print (hex(fl_begin),hex(fl_end), getdw(input_data,0x68), hex(getdw(input_data,0x6C)), hex(getdw(input_data,0x70)), hex(fl_data) )

#
# get "data" section of script
def dta(x):
    if x != 0xffffffff and x != 0:
        return str(input_data[fl_data + x*2:].decode('utf-16')).split("\x00")[0]
    return ' - ';

#print('.');
#print(hex(getdw(input_data, 0x7C)))
#print(hex(getdw(input_data, 0x7C+4)))
#print('.');
#print(hex(getdw(input_data, 0x84)))
#print(hex(getdw(input_data, 0x84+4)))
#print('.');
#print(hex(getdw(input_data, 0x8C)))
#print(hex(getdw(input_data, 0x8C+4)))
#print('.');
#print(hex(getdw(input_data, 0x9C)))
#print(hex(getdw(input_data, 0x9C+4)))
#print('.');
#print(hex(getdw(input_data, 0x94)))
#print(hex(getdw(input_data, 0x94+4)))
#print('.');
#print(hex(getdw(input_data, 0xC)))
#print(hex(getdw(input_data, 0xA5)))
print('\n- Varius strings const:')
print(dta(getdw(input_data, 0x4   )));
print(dta(getdw(input_data, 0x8   )));
print(dta(getdw(input_data, 0x0c  )));
print(dta(getdw(input_data, 0x10  )));
print(dta(getdw(input_data, 0x14  )));
print(dta(getdw(input_data, 0x10  )));

print(dta(getdw(input_data, 0x28  )));
print(dta(getdw(input_data, 0x2C  )));
print(dta(getdw(input_data, 0x30  )));

print(dta(getdw(input_data, 0x48  )));
print(dta(getdw(input_data, 0x50  )));
print(dta(getdw(input_data, 0x54  )));
print(dta(getdw(input_data, 0x5C  )));
print(dta(getdw(input_data, 0x50  )));

print(dta(getdw(input_data, 0x5c  )));

#
# Components
print('\n- Components:');
i=0
while (fl_begin + i < fl_end):
    print(hex(fl_begin + i).ljust(10),':', 
        hex(getdw(input_data, fl_begin + i + 0x00) ).ljust(12), 
        hex(getdw(input_data, fl_begin + i + 0x04) ).ljust(12), 
        hex(getdw(input_data, fl_begin + i + 0x08) ).ljust(12), 
        hex(getdw(input_data, fl_begin + i + 0x0C) ).ljust(12), 
        hex(getdw(input_data, fl_begin + i + 0x10) ).ljust(12),
        dta(getdw(input_data, fl_begin + i + 0x00)),
    )
    i+= 0x14


g_dir = g_extract_dir + '';

# OpCode process
# 
print('\n- process script OpCodes:');

i=0
while (fl_end + i < fl_data):

    if (len(g_filter) > 0) and not(getdw(input_data, fl_end + i + 0x00) in g_filter):
        i+= 0x18
        continue

    if getdw(input_data, fl_end + i + 0x00) == 1: 
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x08))
        )
    elif getdw(input_data, fl_end + i + 0x00) == 2: 
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x04))
        )
    elif getdw(input_data, fl_end + i + 0x00) == 3: #Output directory: %ls"
        print(g_extract_dir );
        g_dir = g_extract_dir + dta(getdw(input_data, fl_end + i + 0x04))
        if g_dir[:-1] != '\\':
            g_dir += '\\'
        os.makedirs(g_dir, exist_ok=True)
        #print(hex(int(i / 0x18)).ljust(4), ':', g_dir)
        #print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
        #    hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
        #    hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
        #    hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
        #    hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
        #    hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
        #    hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
        #    dta(getdw(input_data, fl_end + i + 0x04))
        #)
    elif getdw(input_data, fl_end + i + 0x00) == 4: #Create directory: %ls"
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x04))
        )

    elif getdw(input_data, fl_end + i + 0x00) == 5: #Extract file

        fn = g_dir + dta(getdw(input_data, fl_end + i + 0x08));

        dt=0
        if (getdw(input_data, fl_end + i + 0x10) > 0):
            dt = get_time(input_data[fl_end + i + 0x10:fl_end + i + 0x10+8])

        print(
            #hex(int(i / 0x18)).ljust(4), ':', 
            #hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            #hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), #action
            #hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), #fname
            #hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), #aOfs
            #hex(getdw(input_data, fl_end + i + 0x10) ) +'-'+      #dt
            #hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12), #dt
            #dt,            
            g_dir + dta(getdw(input_data, fl_end + i + 0x08))
        )


        aofs = getdw(input_data, fl_end + i + 0x0C);
        _len = getdw(buff, aofs + 0x20) & 0x7FFFFFFF
        try:
            dd = zlib.decompress(buff[aofs+0x20+4:aofs+0x20+4+_len])
        except:
            #print(hex(aofs+0x20), _len)
            dd = buff[aofs+0x20+4:aofs+0x20+4+_len]

        with open(fn, "wb") as output_file:
           output_file.write(dd)

    elif getdw(input_data, fl_end + i + 0x00) == 6: #Execute
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x04))
        )
    elif getdw(input_data, fl_end + i + 0x00) == 7: #ExecShell
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x04)),
            dta(getdw(input_data, fl_end + i + 0x08)),
            dta(getdw(input_data, fl_end + i + 0x0C)),
        )

    elif getdw(input_data, fl_end + i + 0x00) == 8: #DllFunct
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x04)),
            dta(getdw(input_data, fl_end + i + 0x08)),
            dta(getdw(input_data, fl_end + i + 0x0C))
        )
    elif getdw(input_data, fl_end + i + 0x00) == 9: #is64
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0xA: #Reg Value
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x08)),
            dta(getdw(input_data, fl_end + i + 0x0C)),

            dta(getdw(input_data, fl_end + i + 0x10))
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0xB: #Reg Value Del?
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x08)),
            dta(getdw(input_data, fl_end + i + 0x0C)),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0xC: #updating file
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x04)),
            dta(getdw(input_data, fl_end + i + 0x08)),
            dta(getdw(input_data, fl_end + i + 0x0C)),
            dta(getdw(input_data, fl_end + i + 0x010)),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0xD: #creating shortcut
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x04) ),
            dta(getdw(input_data, fl_end + i + 0x08) ),
            dta(getdw(input_data, fl_end + i + 0x0C) ),
            dta(getdw(input_data, fl_end + i + 0x10) ),
            dta(getdw(input_data, fl_end + i + 0x14) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0xE: #MoveFileEx
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x04) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0xF: #FindWindow
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x08) ),
            dta(getdw(input_data, fl_end + i + 0x0C) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x10: #RetryDialog
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x08) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x11: #RemoveDir
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x4) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x12: #Copying files
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x4) ),
            dta(getdw(input_data, fl_end + i + 0x8) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x13: #Wait
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x14: #SetForegroundWindow
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x15: #ShowWindow
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x16: #FindFirstFileW
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x4) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x17: #MoveFile
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x4) ),
            dta(getdw(input_data, fl_end + i + 0x8) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x18: #File Attributes
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x4) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x19: #AddString
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x4) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x1A: #Show/Hide Window
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x1B: #ErrCode?
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x1C: #??
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x1D: #??
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x8) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x1E: #reg
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0xC) ),
            dta(getdw(input_data, fl_end + i + 0x10) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x1F: #GetPrivateProfileString
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x8) ),
            dta(getdw(input_data, fl_end + i + 0xC) ),
            dta(getdw(input_data, fl_end + i + 0x10) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x20: #lstrcmpiW
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x4) ),
            dta(getdw(input_data, fl_end + i + 0x8) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x21: #lstrcmpiW
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x8) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x22: #sub
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x23: #LoadLib
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x8) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x24: #GetFileVersionInfoSizeW
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x4) ),
            dta(getdw(input_data, fl_end + i + 0x8) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x25: #FileUpdate? GetFileTime
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x4) ),
            dta(getdw(input_data, fl_end + i + 0x8) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x26: #10070, "Update file: %ls"
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x4) ),
            dta(getdw(input_data, fl_end + i + 0x8) ),
            dta(getdw(input_data, fl_end + i + 0xC) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x27:#unk
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x28:#unk
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x29:#SeShutdownPrivilege
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x2A:#unk
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x2B:#Reg get
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0xC) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x2C:#ExecMSI
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x4) ),
            dta(getdw(input_data, fl_end + i + 0x8) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x2D:#Install service
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x4) ),
            dta(getdw(input_data, fl_end + i + 0x8) ),
            dta(getdw(input_data, fl_end + i + 0xC) ),
            dta(getdw(input_data, fl_end + i + 0x14) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x2E:#UnInstall service
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x4) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x2F:#FindFile
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x8) ),
            dta(getdw(input_data, fl_end + i + 0xC) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x30:#unk
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x8) ),
            dta(getdw(input_data, fl_end + i + 0xC) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x31:#CreateShortcut
        print(hex(int(i / 0x18)).ljust(4), hex(fl_end + i).ljust(10),':', 
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
            dta(getdw(input_data, fl_end + i + 0x4) ),
            dta(getdw(input_data, fl_end + i + 0x8) ),
            dta(getdw(input_data, fl_end + i + 0xC) ),
            dta(getdw(input_data, fl_end + i + 0x10) ),
        )
    elif getdw(input_data, fl_end + i + 0x00) == 0x0: #zero op
        print('')
    else:
        print('Unk op',hex(getdw(input_data, fl_end + i + 0x00)),
            hex(getdw(input_data, fl_end + i + 0x00) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x04) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x08) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x0C) ).ljust(12), 
            hex(getdw(input_data, fl_end + i + 0x10) ).ljust(12),
            hex(getdw(input_data, fl_end + i + 0x14) ).ljust(12),
        )
        exit()

    i+= 0x18

print('done');