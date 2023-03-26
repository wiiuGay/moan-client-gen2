print("hi this is the last version pleas try to expand its legacy")
import tkinter as tk					
from tkinter import ttk
from tkinter import *
import tkinter as tkinter
import sys
import os
import struct
import time
import os.path
import socket, sys
from threading import Thread, RLock
import py_compile
import atexit
import webbrowser
config_exist = os.path.isfile("ip.config") 

#===== Imports End =====


#===== TCP Gecko Module ====

import socket, struct
from binascii import hexlify, unhexlify

def enum(**enums):
    return type('Enum', (), enums)

class TCPGecko:
    def __init__(self, *args):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        print("Connecting to " + str(args[0]) + ":7331")
        self.s.connect((str(args[0]), 7331)) #IP, 1337 reversed, Cafiine uses 7332+
        print("Connected!")

    def readmem(self, address, length): #Number of bytes
        if length == 0: raise BaseException("Reading memory requires a length (# of bytes)")
        if not self.validrange(address, length): raise BaseException("Address range not valid")
        if not self.validaccess(address, length, "read"): raise BaseException("Cannot read from address")
        ret = b""
        if length > 0x400:
            print("Length is greater than 0x400 bytes, need to read in chunks")
            print("Start address:   " + hexstr0(address))
            for i in range(int(length / 0x400)): #Number of blocks, ignores extra
                self.s.send(b"\x04") #cmd_readmem
                request = struct.pack(">II", address, address + 0x400)
                self.s.send(request)
                status = self.s.recv(1)
                if   status == b"\xbd": ret += self.s.recv(0x400)
                elif status == b"\xb0": ret += b"\x00" * 0x400
                else: raise BaseException("Something went terribly wrong")
                address += 0x400;length -= 0x400
                print("Current address: " + hexstr0(address))
            if length != 0: #Now read the last little bit
                self.s.send(b"\x04")
                request = struct.pack(">II", address, address + length)
                self.s.send(request)
                status = self.s.recv(1)
                if   status == b"\xbd": ret += self.s.recv(length)
                elif status == b"\xb0": ret += b"\x00" * length
                else: raise BaseException("Something went terribly wrong")
            print("Finished!")
        else:
            self.s.send(b"\x04")
            request = struct.pack(">II", address, address + length)
            self.s.send(request)
            status = self.s.recv(1)
            if   status == b"\xbd": ret += self.s.recv(length)
            elif status == b"\xb0": ret += b"\x00" * length
            else: raise BaseException("Something went terribly wrong")
        return ret

    def readkern(self, address): #Only takes 4 bytes, may need to run multiple times
        if not self.validrange(address, 4): raise BaseException("Address range not valid")
        if not self.validaccess(address, 4, "write"): raise BaseException("Cannot write to address")
        self.s.send(b"\x0C") #cmd_readkern
        request = struct.pack(">I", int(address))
        self.s.send(request)
        value  = struct.unpack(">I", self.s.recv(4))[0]
        return value

    def writekern(self, address, value): #Only takes 4 bytes, may need to run multiple times
        if not self.validrange(address, 4): raise BaseException("Address range not valid")
        if not self.validaccess(address, 4, "write"): raise BaseException("Cannot write to address")
        self.s.send(b"\x0B") #cmd_readkern
        print(value)
        request = struct.pack(">II", int(address), int(value))
        self.s.send(request)
        return

    def pokemem(self, address, value): #Only takes 4 bytes, may need to run multiple times
        if not self.validrange(address, 4): raise BaseException("Address range not valid")
        if not self.validaccess(address, 4, "write"): raise BaseException("Cannot write to address")
        self.s.send(b"\x03") #cmd_pokemem
        request = struct.pack(">II", int(address), int(value))
        self.s.send(request) #Done, move on
        return
		
    def pokemem8(self, address, value): #Only takes 4 bytes, may need to run multiple times
        if not self.validrange(address, 4): raise BaseException("Address range not valid")
        if not self.validaccess(address, 4, "write"): raise BaseException("Cannot write to address")
        self.s.send(b"\x03") #cmd_pokemem
        request = struct.pack(">IB", int(address), int(value))
        self.s.send(request) #Done, move on
        return

    def search32(self, address, value, size):
        self.s.send(b"\x72") #cmd_search32
        request = struct.pack(">III", address, value, size)
        self.s.send(request)
        reply = self.s.recv(4)
        return struct.unpack(">I", reply)[0]

    def getversion(self):
        self.s.send(b"\x9A") #cmd_os_version
        reply = self.s.recv(4)
        return struct.unpack(">I", reply)[0]

    def writestr(self, address, string):
        if not self.validrange(address, len(string)): raise BaseException("Address range not valid")
        if not self.validaccess(address, len(string), "write"): raise BaseException("Cannot write to address")
        if type(string) != bytes: string = bytes(string, "UTF-8") #Sanitize
        if len(string) % 4: string += bytes((4 - (len(string) % 4)) * b"\x00")
        pos = 0
        for x in range(int(len(string) / 4)):
            self.pokemem(address, struct.unpack(">I", string[pos:pos + 4])[0])
            address += 4;pos += 4
        return
        
    def memalign(self, size, align):
        symbol = self.get_symbol("coreinit.rpl", "MEMAllocFromDefaultHeapEx", True, 1)
        symbol = struct.unpack(">I", symbol.address)[0]
        address = self.readmem(symbol, 4)
        #print("memalign address: " + hexstr0(struct.unpack(">I", address)[0]))
        ret = self.call(address, size, align)
        return ret

    def freemem(self, address):
        symbol = self.get_symbol("coreinit.rpl", "MEMFreeToDefaultHeap", True, 1)
        symbol = struct.unpack(">I", symbol.address)[0]
        addr = self.readmem(symbol, 4)
        #print("freemem address: " + hexstr0(struct.unpack(">I", addr)[0]))
        self.call(addr, address) #void, no return

    def memalloc(self, size, align, noprint=False):
        return self.function("coreinit.rpl", "OSAllocFromSystem", noprint, 0, size, align)

    def freealloc(self, address):
        return self.function("coreinit.rpl", "OSFreeToSystem", True, 0, address)

    def createpath(self, path):
        if not hasattr(self, "pPath"): self.pPath = self.memalloc(len(path), 0x20, True) #It'll auto-pad
        size = len(path) + (32 - (len(path) % 32))
        self.function("coreinit.rpl", "memset", True, 0, self.pPath, 0x00, size)
        self.writestr(self.pPath, path)
        #print("pPath address: " + hexstr0(self.pPath))

    def createstr(self, string):
        address = self.memalloc(len(string), 0x20, True) #It'll auto-pad
        size = len(string) + (32 - (len(string) % 32))
        self.function("coreinit.rpl", "memset", True, 0, address, 0x00, size)
        self.writestr(address, string)
        print("String address: " + hexstr0(address))
        return address

    def FSInitClient(self):
        self.pClient = self.memalign(0x1700, 0x20)
        self.function("coreinit.rpl", "FSAddClient", True, 0, self.pClient)
        #print("pClient address: " + hexstr0(self.pClient))

    def FSInitCmdBlock(self):
        self.pCmd = self.memalign(0xA80, 0x20)
        self.function("coreinit.rpl", "FSInitCmdBlock", True, 0, self.pCmd)
        #print("pCmd address:    " + hexstr0(self.pCmd))

    def FSOpenDir(self, path="/"):
        print("Initializing...")
        self.function("coreinit.rpl",  "FSInit", True)
        if not hasattr(self, "pClient"): self.FSInitClient()
        if not hasattr(self, "pCmd"):    self.FSInitCmdBlock()
        print("Getting memory ready...")
        self.createpath(path)
        self.pDh   = self.memalloc(4, 4, True)
        #print("pDh address: " + hexstr0(self.pDh))
        print("Calling function...")
        ret = self.function("coreinit.rpl", "FSOpenDir", False, 0, self.pClient, self.pCmd, self.pPath, self.pDh, 0xFFFFFFFF)
        self.pDh = int(hexlify(self.readmem(self.pDh, 4)), 16)
        print("Return value: " + hexstr0(ret))

    def SAVEOpenDir(self, path="/", slot=255):
        print("Initializing...")
        self.function("coreinit.rpl",  "FSInit", True, 0)
        self.function("nn_save.rpl", "SAVEInit", True, 0, slot)
        print("Getting memory ready...")
        if not hasattr(self, "pClient"): self.FSInitClient()
        if not hasattr(self, "pCmd"):    self.FSInitCmdBlock()
        self.createpath(path)
        self.pDh   = self.memalloc(4, 4, True)
        #print("pDh address: " + hexstr0(self.pDh))
        print("Calling function...")
        ret = self.function("nn_save.rpl", "SAVEOpenDir", False, 0, self.pClient, self.pCmd, slot, self.pPath, self.pDh, 0xFFFFFFFF)
        self.pDh = int(hexlify(self.readmem(self.pDh, 4)), 16)
        print("Return value: " + hexstr0(ret))

    def FSReadDir(self):
        global printe
        if not hasattr(self, "pBuffer"): self.pBuffer = self.memalign(0x164, 0x20)
        print("pBuffer address: " + hexstr0(self.pBuffer))
        ret = self.function("coreinit.rpl", "FSReadDir", True, 0, self.pClient, self.pCmd, self.pDh, self.pBuffer, 0xFFFFFFFF)
        self.entry = self.readmem(self.pBuffer, 0x164)
        printe = getstr(self.entry, 100) + " "
        self.FileSystem().printflags(uint32(self.entry, 0), self.entry)
        self.FileSystem().printperms(uint32(self.entry, 4))
        print(printe)
        return self.entry, ret

    def SAVEOpenFile(self, path="/", mode="r", slot=255):
        print("Initializing...")
        self.function("coreinit.rpl",  "FSInit", True)
        self.function("nn_save.rpl", "SAVEInit", slot, True)
        print("Getting memory ready...")
        if not hasattr(self, "pClient"): self.FSInitClient()
        if not hasattr(self, "pCmd"):    self.FSInitCmdBlock()
        self.createpath(path)
        self.pMode = self.createstr(mode)
        self.pFh   = self.memalign(4, 4)
        #print("pFh address: " + hexstr0(self.pFh))
        print("Calling function...")
        print("This function may have errors")
        #ret = self.function("nn_save.rpl", "SAVEOpenFile", self.pClient, self.pCmd, slot, self.pPath, self.pMode, self.pFh, 0xFFFFFFFF)
        #self.pFh = int(self.readmem(self.pFh, 4).encode("hex"), 16)
        #print(ret)

    def FSReadFile(self):
        if not hasattr(self, "pBuffer"): self.pBuffer = self.memalign(0x200, 0x20)
        print("pBuffer address: " + hexstr0(self.pBuffer))
        ret = self.function("coreinit.rpl", "FSReadFile", False, 0, self.pClient, self.pCmd, self.pBuffer, 1, 0x200, self.pFh, 0, 0xFFFFFFFF)
        print(ret)
        return tcp.readmem(self.pBuffer, 0x200)

    def get_symbol(self, rplname, symname, noprint=False, data=0):
        self.s.send(b"\x71") #cmd_getsymbol
        request = struct.pack(">II", 8, 8 + len(rplname) + 1) #Pointers
        request += rplname.encode("UTF-8") + b"\x00"
        request += symname.encode("UTF-8") + b"\x00"
        size = struct.pack(">B", len(request))
        data = struct.pack(">B", data)
        self.s.send(size) #Read this many bytes
        self.s.send(request) #Get this symbol
        self.s.send(data) #Is it data?
        address = self.s.recv(4)
        return ExportedSymbol(address, self, rplname, symname, noprint)

    def call(self, address, *args):
        arguments = list(args)
        if len(arguments)>8 and len(arguments)<=16: #Use the big call function
            while len(arguments) != 16:
                arguments.append(0)
            self.s.send(b"\x80")
            address = struct.unpack(">I", address)[0]
            request = struct.pack(">I16I", address, *arguments)
            self.s.send(request)
            reply = self.s.recv(8)
            return struct.unpack(">I", reply[:4])[0]
        elif len(arguments) <= 8: #Use the normal one that dNet client uses
            while len(arguments) != 8:
                arguments.append(0)
            self.s.send(b"\x70")
            address = struct.unpack(">I", address)[0]
            request = struct.pack(">I8I", address, *arguments)
            self.s.send(request)
            reply = self.s.recv(8)
            return struct.unpack(">I", reply[:4])[0]
        else: raise BaseException("Too many arguments!")

    #Data last, only a few functions need it, noprint for the big FS/SAVE ones above, acts as gateway for data arg
    def function(self, rplname, symname, noprint=False, data=0, *args):
        symbol = self.get_symbol(rplname, symname, noprint, data)
        ret = self.call(symbol.address, *args)
        return ret

    def validrange(self, address, length):
        if   0x01000000 <= address and address + length <= 0x01800000: return True
        elif 0x02000000 <= address and address + length <= 0x10000000: return True #Depends on game
        elif 0x10000000 <= address and address + length <= 0x50000000: return True #Doesn't quite go to 5
        elif 0xE0000000 <= address and address + length <= 0xE4000000: return True
        elif 0xE8000000 <= address and address + length <= 0xEA000000: return True
        elif 0xF4000000 <= address and address + length <= 0xF6000000: return True
        elif 0xF6000000 <= address and address + length <= 0xF6800000: return True
        elif 0xF8000000 <= address and address + length <= 0xFB000000: return True
        elif 0xFB000000 <= address and address + length <= 0xFB800000: return True
        elif 0xFFFE0000 <= address and address + length <= 0xFFFFFFFF: return True
        else: return True

    def validaccess(self, address, length, access):
        if   0x01000000 <= address and address + length <= 0x01800000:
            if access.lower() == "read":  return True
            if access.lower() == "write": return True
        elif 0x02000000 <= address and address + length <= 0x10000000: #Depends on game, may be EG 0x0E3
            if access.lower() == "read":  return True
            if access.lower() == "write": return True
        elif 0x10000000 <= address and address + length <= 0x50000000:
            if access.lower() == "read":  return True
            if access.lower() == "write": return True
        elif 0xE0000000 <= address and address + length <= 0xE4000000:
            if access.lower() == "read":  return True
            if access.lower() == "write": return True
        elif 0xE8000000 <= address and address + length <= 0xEA000000:
            if access.lower() == "read":  return True
            if access.lower() == "write": return True
        elif 0xF4000000 <= address and address + length <= 0xF6000000:
            if access.lower() == "read":  return True
            if access.lower() == "write": return True
        elif 0xF6000000 <= address and address + length <= 0xF6800000:
            if access.lower() == "read":  return True
            if access.lower() == "write": return True
        elif 0xF8000000 <= address and address + length <= 0xFB000000:
            if access.lower() == "read":  return True
            if access.lower() == "write": return True
        elif 0xFB000000 <= address and address + length <= 0xFB800000:
            if access.lower() == "read":  return True
            if access.lower() == "write": return True
        elif 0xFFFE0000 <= address and address + length <= 0xFFFFFFFF:
            if access.lower() == "read":  return True
            if access.lower() == "write": return True
        else: return False
        
    class FileSystem: #TODO: Try to clean this up ????
        Flags = enum(
            IS_DIRECTORY    = 0x80000000,
            IS_QUOTA        = 0x40000000,
            SPRT_QUOTA_SIZE = 0x20000000, #Supports .quota_size field
            SPRT_ENT_ID     = 0x10000000, #Supports .ent_id field
            SPRT_CTIME      = 0x08000000, #Supports .ctime field
            SPRT_MTIME      = 0x04000000, #Supports .mtime field
            SPRT_ATTRIBUTES = 0x02000000, #Supports .attributes field
            SPRT_ALLOC_SIZE = 0x01000000, #Supports .alloc_size field
            IS_RAW_FILE     = 0x00800000, #Entry isn't encrypted
            SPRT_DIR_SIZE   = 0x00100000, #Supports .size field, doesn't apply to files
            UNSUPPORTED_CHR = 0x00080000) #Entry name has an unsupported character
        
        Permissions = enum( #Pretty self explanitory
            OWNER_READ  = 0x00004000,
            OWNER_WRITE = 0x00002000,
            OTHER_READ  = 0x00000400,
            OTHER_WRITE = 0x00000200)

        def printflags(self, flags, data):
            global printe
            if flags & self.Flags.IS_DIRECTORY:    printe += " Directory"
            if flags & self.Flags.IS_QUOTA:        printe += " Quota"
            if flags & self.Flags.SPRT_QUOTA_SIZE: printe += " .quota_size: " + hexstr0(uint32(data, 24))
            if flags & self.Flags.SPRT_ENT_ID:     printe += " .ent_id: " + hexstr0(uint32(data, 32))
            if flags & self.Flags.SPRT_CTIME:      printe += " .ctime: " + hexstr0(uint32(data, 36))
            if flags & self.Flags.SPRT_MTIME:      printe += " .mtime: " + hexstr0(uint32(data, 44))
            if flags & self.Flags.SPRT_ATTRIBUTES: pass #weh
            if flags & self.Flags.SPRT_ALLOC_SIZE: printe += " .alloc_size: " + hexstr0(uint32(data, 20))
            if flags & self.Flags.IS_RAW_FILE:     printe += " Raw (Unencrypted) file"
            if flags & self.Flags.SPRT_DIR_SIZE:   printe += " .dir_size: " + hexstr0(uint32(data, 24))
            if flags & self.Flags.UNSUPPORTED_CHR: printe += " !! UNSUPPORTED CHARACTER IN NAME"

        def printperms(self, perms):
            global printe
            if perms & self.Permissions.OWNER_READ:  printe += " OWNER_READ"
            if perms & self.Permissions.OWNER_WRITE: printe += " OWNER_WRITE"
            if perms & self.Permissions.OTHER_READ:  printe += " OTHER_READ"
            if perms & self.Permissions.OTHER_WRITE: printe += " OTHER_WRITE"
                
def hexstr0(data): #0xFFFFFFFF, uppercase hex string
    return "0x" + hex(data).lstrip("0x").rstrip("L").zfill(8).upper()

class ExportedSymbol(object):
    def __init__(self, address, rpc=None, rplname=None, symname=None, noprint=False):
        self.address = address
        self.rpc     = rpc
        self.rplname = rplname
        self.symname = symname
        if not noprint: #Make command prompt not explode when using FS or SAVE functions
            print(symname + " address: " + hexstr0(struct.unpack(">I", address)[0]))

    def __call__(self, *args):
        return self.rpc.call(self.address, *args) #Pass in arguments, run address
        
class switch(object): #Taken from http://code.activestate.com/recipes/410692/
    def __init__(self, value):
        self.value = value
        self.fall = False

    def __iter__(self):
        """Return the match method once, then stop"""
        yield self.match
        raise StopIteration
    
    def match(self, *args):
        """Indicate whether or not to enter a case suite"""
        if self.fall or not args:
            return True
        elif self.value in args:
            self.fall = True
            return True
        else:
            return False
'''Example Use Case for switch:
for case in switch(variable):
    if case(0):
        #dostuff
    elif case(1):
        #dostuff
    else: #default
        #dodefaultstuff'''

def hexstr(data, length): #Pad hex to value for prettyprint
    return hex(data).lstrip("0x").rstrip("L").zfill(length).upper()
def hexstr0(data): #Uppercase hex to string
    return "0x" + hex(data).lstrip("0x").rstrip("L").upper()
def binr(byte): #Get bits as a string
    return bin(byte).lstrip("0b").zfill(8)
def uint8(data, pos):
    return struct.unpack(">B", data[pos:pos + 1])[0]
def uint16(data, pos):
    return struct.unpack(">H", data[pos:pos + 2])[0]
def uint24(data, pos):
    return struct.unpack(">I", "\00" + data[pos:pos + 3])[0] #HAX
def uint32(data, pos):
    return struct.unpack(">I", data[pos:pos + 4])[0]

def getstr(data, pos): #Keep incrementing till you hit a stop
    string = ""
    while data[pos] != 0:
        if pos != len(data):
            string += chr(data[pos])
            pos += 1
        else: break
    return string


#===== TCP Gecko Module End ====

#===== Main Window =====

s1_ptr = 0x112395AC
s2_ptr = 0x112395B4
s3_ptr = 0x112395B0
name_ptr = 0x121F2C94

freemem = 0x3F000000

def str_end(string, ind):
	for i in range(0, 0xFFFF):
		x = string[ind+i:ind+i+1:1]
		if x == "\x00":
			return string[ind:ind+i:1]


window = Tk()
window.title('moan injectorV1.14')
window.geometry('655x150')
tabControl = ttk.Notebook(window)

tab1 = ttk.Frame(tabControl)
tab2 = ttk.Frame(tabControl)
tab3 = ttk.Frame(tabControl)

tabControl.add(tab1, text ='ip')
tabControl.add(tab2, text ='mod')
tabControl.add(tab3, text ='othere things')
tabControl.grid(columnspan = 1, rowspan = 1)

# Print Logo
print("""
██╗  ██╗ ██████╗ ██████╗  ██████╗ ███████╗██╗███╗   ██╗    ██████╗ ████████╗███╗   ███╗    ██╗   ██╗███████╗m
██║ ██╔╝██╔═══██╗██╔══██╗██╔═══██╗╚══███╔╝██║████╗  ██║    ██╔══██╗╚══██╔══╝████╗ ████║    ██║   ██║██╔════╝o
█████╔╝ ██║   ██║██████╔╝██║   ██║  ███╔╝ ██║██╔██╗ ██║    ██████╔╝   ██║   ██╔████╔██║    ██║   ██║███████╗d
██╔═██╗ ██║   ██║██╔══██╗██║   ██║ ███╔╝  ██║██║╚██╗██║    ██╔══██╗   ██║   ██║╚██╔╝██║    ╚██╗ ██╔╝╚════██║d
██║  ██╗╚██████╔╝██║  ██║╚██████╔╝███████╗██║██║ ╚████║    ██║  ██║   ██║   ██║ ╚═╝ ██║     ╚████╔╝ ███████║e
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝    ╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝      ╚═══╝  ╚══════╝d       
""")

#===== Main Window End =====

#===== Section: Tab 1 =====

verrou = RLock()

def connect():
	ip = nip.get()
	global tcp, f_config
	tcp = TCPGecko(ip)
	x = tcp.readmem(name_ptr, 20)
	x = str_end(x, 0)
	tcp.pokemem(0x1076f7a8, 0x000000FF)
	temp_vars = []
	f_config.seek(0, 0)
	f_config.write(ip)
	f_config.close()
	
def disc():
	with verrou:
		global temp_vars
		temp_vars = []
		tcp.s.close()
		print("Disconnected.")
		
blank = Label(tab1, text="Connection")
blank.grid(row=0, column = 0)

if config_exist == False:
	nip = StringVar()
	nip.set("Wii U IP Addr")
	f_config = open("ip.config", "a+")
else:
	nip = StringVar()
	f_config = open("ip.config", "r+")
	nip.set(f_config.read())

n_ip = Entry(tab1, textvariable=nip)
n_ip.grid(row=1, column=0)

cnn = Button(tab1, text="Connect", command=connect)
cnn.grid(row=1, column=1)

b_disconnect = Button(tab1, text="Disconnect", command=disc)
b_disconnect.grid(row=1, column=2)

#===== Section: Tab 1 End =====

#===== Section: Defined Functions =====

def kickNt2():
    if cb.get() == 1:

        tcp.pokemem(0x3052720, 0x3C403005)
        tcp.pokemem(0x03052720, 0x4E800020)

        print("cheaters favrot mod")
        
    elif cb.get() == 3:

        tcp.pokemem(0x02E9B1B0, 0x7FC4F378)

        print("Armor Hud Disabled")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def fly2():
    if cb2.get() == 1:

        tcp.pokemem(0x271AA74, 0x38600001)
    print("fly like a bird")
        

    
        
def craftAll():
    if cb3.get() == 3:

        tcp.pokemem(0x02F70970, 0x38600001)
        tcp.pokemem(0x032283CC, 0x38800001)
        tcp.pokemem(0x02F59534, 0x7C0802A6)

        print("Craft all now active!")
        
    elif cb3.get() == 4:

        tcp.pokemem(0x02F70970, 0x38600000)

        print("Disabling has not yet been implemented for this code")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def fly():
    if cb4.get() == 5:

        tcp.pokemem(0x31B2B4C, 38600001)

   
def FOFbypass():
    if cb5.get() == 1:

        tcp.pokemem(0x02D5731C, 0x38600001)
        tcp.pokemem(0x02D57320, 0x4E800020)

        print("You can now bypass Friends of Friends!")
        
    elif cb5.get() == 8:

        tcp.pokemem(0x02D5731C, 0x7C0802A6)
        tcp.pokemem(0x02D57320, 0x9421FFF0)

        print("FOF Disabled")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def pot():
    if cb6.get() == 1:

        tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x12100001, 0x000006D8)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000028)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000000C)
    #tcp.pokemem(0x00120000, 0x00000040)
    tcp.pokemem(0x13100001, 0x00000008)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000002C)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000000C)
    tcp.pokemem(0x00120000, 0x00000040)
    tcp.pokemem(0x13100001, 0x00000008)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000030)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000000C)
    tcp.pokemem(0x00120000, 0x00000040)
    tcp.pokemem(0x13100001, 0x00000008)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000034)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000000C)
    tcp.pokemem(0x00120000, 0x00000040)
    tcp.pokemem(0x13100001, 0x00000008)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000038)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000000C)
    tcp.pokemem(0x00120000, 0x00000040)
    tcp.pokemem(0x13100001, 0x00000008)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000003C)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000000C)
    tcp.pokemem(0x00120000, 0x00000040)
    tcp.pokemem(0x13100001, 0x00000008)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000040)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000000C)
    tcp.pokemem(0x00120000, 0x00000040)
    tcp.pokemem(0x13100001, 0x00000008)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000044)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000000C)
    tcp.pokemem(0x00120000, 0x00000040)
    tcp.pokemem(0x13100001, 0x00000008)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000048)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000000C)
    tcp.pokemem(0x00120000, 0x00000040)
    tcp.pokemem(0x13100001, 0x00000008)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000004C)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000000C)
    tcp.pokemem(0x00120000, 0x00000040)
    tcp.pokemem(0x13100001, 0x00000008)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000050)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000000C)
    tcp.pokemem(0x00120000, 0x00000040)
    tcp.pokemem(0x13100001, 0x00000008)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000054)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000000C)
    tcp.pokemem(0x00120000, 0x00000040)
    tcp.pokemem(0x13100001, 0x00000008)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000058)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000000C)
    tcp.pokemem(0x00120000, 0x00000040)
    tcp.pokemem(0x13100001, 0x00000008)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000005C)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000000C)
    tcp.pokemem(0x00120000, 0x00000040)
    tcp.pokemem(0x13100001, 0x00000008)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000060)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000000C)
    tcp.pokemem(0x00120000, 0x00000040)
    tcp.pokemem(0x13100001, 0x00000008)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000002B0)
    tcp.pokemem(0x00120000, 0x00430075)
    tcp.pokemem(0x00120004, 0x00730074)
    tcp.pokemem(0x00120008, 0x006F006D)
    tcp.pokemem(0x0012000C, 0x0050006F)
    tcp.pokemem(0x00120010, 0x00740069)
    tcp.pokemem(0x00120014, 0x006F006E)
    tcp.pokemem(0x00120018, 0x00450066)
    tcp.pokemem(0x0012001C, 0x00660065)
    tcp.pokemem(0x00120020, 0x00630074)
    tcp.pokemem(0x00120024, 0x00730000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000020C)
    tcp.pokemem(0x00120000, 0x00490064)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001B4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000026C)
    tcp.pokemem(0x00120000, 0x0018CCA4)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001BC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000088)
    tcp.pokemem(0x00120000, 0x1065993C)
    tcp.pokemem(0x00120004, 0x7FFFFFFF)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000018C)
    tcp.pokemem(0x00120000, 0x00440075)
    tcp.pokemem(0x00120004, 0x00720061)
    tcp.pokemem(0x00120008, 0x00740069)
    tcp.pokemem(0x0012000C, 0x006F006E)
    tcp.pokemem(0x00120010, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000028)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000018)
    tcp.pokemem(0x13100071, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x12100071, 0x00000018)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000002B0)
    tcp.pokemem(0x00120000, 0x00430075)
    tcp.pokemem(0x00120004, 0x00730074)
    tcp.pokemem(0x00120008, 0x006F006D)
    tcp.pokemem(0x0012000C, 0x0050006F)
    tcp.pokemem(0x00120010, 0x00740069)
    tcp.pokemem(0x00120014, 0x006F006E)
    tcp.pokemem(0x00120018, 0x00450066)
    tcp.pokemem(0x0012001C, 0x00660065)
    tcp.pokemem(0x00120020, 0x00630074)
    tcp.pokemem(0x00120024, 0x00730000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000020C)
    tcp.pokemem(0x00120000, 0x00490064)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001B8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000026C)
    tcp.pokemem(0x00120000, 0x0019CCA4)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000088)
    tcp.pokemem(0x00120000, 0x1065993C)
    tcp.pokemem(0x00120004, 0x7FFFFFFF)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000018C)
    tcp.pokemem(0x00120000, 0x00440075)
    tcp.pokemem(0x00120004, 0x00720061)
    tcp.pokemem(0x00120008, 0x00740069)
    tcp.pokemem(0x0012000C, 0x006F006E)
    tcp.pokemem(0x00120010, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000002C)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000018)
    tcp.pokemem(0x13100072, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x12100072, 0x00000018)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000002B0)
    tcp.pokemem(0x00120000, 0x00430075)
    tcp.pokemem(0x00120004, 0x00730074)
    tcp.pokemem(0x00120008, 0x006F006D)
    tcp.pokemem(0x0012000C, 0x0050006F)
    tcp.pokemem(0x00120010, 0x00740069)
    tcp.pokemem(0x00120014, 0x006F006E)
    tcp.pokemem(0x00120018, 0x00450066)
    tcp.pokemem(0x0012001C, 0x00660065)
    tcp.pokemem(0x00120020, 0x00630074)
    tcp.pokemem(0x00120024, 0x00730000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000020C)
    tcp.pokemem(0x00120000, 0x00490064)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001BC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000026C)
    tcp.pokemem(0x00120000, 0x0009CCA4)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000088)
    tcp.pokemem(0x00120000, 0x1065993C)
    tcp.pokemem(0x00120004, 0x7FFFFFFF)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000018C)
    tcp.pokemem(0x00120000, 0x00440075)
    tcp.pokemem(0x00120004, 0x00720061)
    tcp.pokemem(0x00120008, 0x00740069)
    tcp.pokemem(0x0012000C, 0x006F006E)
    tcp.pokemem(0x00120010, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000030)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000018)
    tcp.pokemem(0x13100073, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001CC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x12100073, 0x00000018)
    tcp.pokemem(0x30000000,0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001CC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000002B0)
    tcp.pokemem(0x00120000, 0x00430075)
    tcp.pokemem(0x00120004, 0x00730074)
    tcp.pokemem(0x00120008, 0x006F006D)
    tcp.pokemem(0x0012000C, 0x0050006F)
    tcp.pokemem(0x00120010, 0x00740069)
    tcp.pokemem(0x00120014, 0x006F006E)
    tcp.pokemem(0x00120018, 0x00450066)
    tcp.pokemem(0x0012001C, 0x00660065)
    tcp.pokemem(0x00120020, 0x00630074)
    tcp.pokemem(0x00120024, 0x00730000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001CC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000020C)
    tcp.pokemem(0x00120000, 0x00490064)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000026C)
    tcp.pokemem(0x00120000, 0x000FCCA4)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000088)
    tcp.pokemem(0x00120000, 0x1065993C)
    tcp.pokemem(0x00120004, 0x7FFFFFFF)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001CC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000018C)
    tcp.pokemem(0x00120000, 0x00440075)
    tcp.pokemem(0x00120004, 0x00720061)
    tcp.pokemem(0x00120008, 0x00740069)
    tcp.pokemem(0x0012000C, 0x006F006E)
    tcp.pokemem(0x00120010, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000034)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000018)
    tcp.pokemem(0x13100074, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x12100074, 0x00000018)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000002B0)
    tcp.pokemem(0x00120000, 0x00430075)
    tcp.pokemem(0x00120004, 0x00730074)
    tcp.pokemem(0x00120008, 0x006F006D)
    tcp.pokemem(0x0012000C, 0x0050006F)
    tcp.pokemem(0x00120010, 0x00740069)
    tcp.pokemem(0x00120014, 0x006F006E)
    tcp.pokemem(0x00120018, 0x00450066)
    tcp.pokemem(0x0012001C, 0x00660065)
    tcp.pokemem(0x00120020, 0x00630074)
    tcp.pokemem(0x00120024, 0x00730000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000020C)
    tcp.pokemem(0x00120000, 0x00490064)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000026C)
    tcp.pokemem(0x00120000, 0x0011CCA4)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001CC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000088)
    tcp.pokemem(0x00120000, 0x1065993C)
    tcp.pokemem(0x00120004, 0x7FFFFFFF)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000018C)
    tcp.pokemem(0x00120000, 0x00440075)
    tcp.pokemem(0x00120004, 0x00720061)
    tcp.pokemem(0x00120008, 0x00740069)
    tcp.pokemem(0x0012000C, 0x006F006E)
    tcp.pokemem(0x00120010, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000038)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000018)
    tcp.pokemem(0x13100075, 0x00000000)
    tcp.pokemem(0x30000000,0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x12100075, 0x00000018)
    tcp.pokemem(0x30000000,0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000002B0)
    tcp.pokemem(0x00120000, 0x00430075)
    tcp.pokemem(0x00120004, 0x00730074)
    tcp.pokemem(0x00120008, 0x006F006D)
    tcp.pokemem(0x0012000C, 0x0050006F)
    tcp.pokemem(0x00120010, 0x00740069)
    tcp.pokemem(0x00120014, 0x006F006E)
    tcp.pokemem(0x00120018, 0x00450066)
    tcp.pokemem(0x0012001C, 0x00660065)
    tcp.pokemem(0x00120020, 0x00630074)
    tcp.pokemem(0x00120024, 0x00730000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000020C)
    tcp.pokemem(0x00120000, 0x00490064)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001C8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000026C)
    tcp.pokemem(0x00120000, 0x0004CCA4)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000088)
    tcp.pokemem(0x00120000, 0x1065993C)
    tcp.pokemem(0x00120004, 0x7FFFFFFF)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000018C)
    tcp.pokemem(0x00120000, 0x00440075)
    tcp.pokemem(0x00120004, 0x00720061)
    tcp.pokemem(0x00120008, 0x00740069)
    tcp.pokemem(0x0012000C, 0x006F006E)
    tcp.pokemem(0x00120010, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000003C)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000018)
    tcp.pokemem(0x13100076, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x12100076, 0x00000018)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000002B0)
    tcp.pokemem(0x00120000, 0x00430075)
    tcp.pokemem(0x00120004, 0x00730074)
    tcp.pokemem(0x00120008, 0x006F006D)
    tcp.pokemem(0x0012000C, 0x0050006F)
    tcp.pokemem(0x00120010, 0x00740069)
    tcp.pokemem(0x00120014, 0x006F006E)
    tcp.pokemem(0x00120018, 0x00450066)
    tcp.pokemem(0x0012001C, 0x00660065)
    tcp.pokemem(0x00120020, 0x00630074)
    tcp.pokemem(0x00120024, 0x00730000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000020C)
    tcp.pokemem(0x00120000, 0x00490064)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001CC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000026C)
    tcp.pokemem(0x00120000, 0x0015CCA4)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000088)
    tcp.pokemem(0x00120000, 0x1065993C)
    tcp.pokemem(0x00120004, 0x7FFFFFFF)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000018C)
    tcp.pokemem(0x00120000, 0x00440075)
    tcp.pokemem(0x00120004, 0x00720061)
    tcp.pokemem(0x00120008, 0x00740069)
    tcp.pokemem(0x0012000C, 0x006F006E)
    tcp.pokemem(0x00120010, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000040)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000018)
    tcp.pokemem(0x13100077, 0x00000000)
    tcp.pokemem(0x30000000,0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001DC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x12100077, 0x00000018)
    tcp.pokemem(0x30000000,0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001DC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000002B0)
    tcp.pokemem(0x00120000, 0x00430075)
    tcp.pokemem(0x00120004, 0x00730074)
    tcp.pokemem(0x00120008, 0x006F006D)
    tcp.pokemem(0x0012000C, 0x0050006F)
    tcp.pokemem(0x00120010, 0x00740069)
    tcp.pokemem(0x00120014, 0x006F006E)
    tcp.pokemem(0x00120018, 0x00450066)
    tcp.pokemem(0x0012001C, 0x00660065)
    tcp.pokemem(0x00120020, 0x00630074)
    tcp.pokemem(0x00120024, 0x00730000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001DC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000020C)
    tcp.pokemem(0x00120000, 0x00490064)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000026C)
    tcp.pokemem(0x00120000, 0x001CCCA4)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000088)
    tcp.pokemem(0x00120000, 0x1065993C)
    tcp.pokemem(0x00120004, 0x7FFFFFFF)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001DC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000018C)
    tcp.pokemem(0x00120000, 0x00440075)
    tcp.pokemem(0x00120004, 0x00720061)
    tcp.pokemem(0x00120008, 0x00740069)
    tcp.pokemem(0x0012000C, 0x006F006E)
    tcp.pokemem(0x00120010, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000044)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000018)
    tcp.pokemem(0x13100078, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x12100078, 0x00000018)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000002B0)
    tcp.pokemem(0x00120000, 0x00430075)
    tcp.pokemem(0x00120004, 0x00730074)
    tcp.pokemem(0x00120008, 0x006F006D)
    tcp.pokemem(0x0012000C, 0x0050006F)
    tcp.pokemem(0x00120010, 0x00740069)
    tcp.pokemem(0x00120014, 0x006F006E)
    tcp.pokemem(0x00120018, 0x00450066)
    tcp.pokemem(0x0012001C, 0x00660065)
    tcp.pokemem(0x00120020, 0x00630074)
    tcp.pokemem(0x00120024, 0x00730000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000020C)
    tcp.pokemem(0x00120000, 0x00490064)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000026C)
    tcp.pokemem(0x00120000, 0x001BCCA4)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001DC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000088)
    tcp.pokemem(0x00120000, 0x1065993C)
    tcp.pokemem(0x00120004, 0x7FFFFFFF)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000018C)
    tcp.pokemem(0x00120000, 0x00440075)
    tcp.pokemem(0x00120004, 0x00720061)
    tcp.pokemem(0x00120008, 0x00740069)
    tcp.pokemem(0x0012000C, 0x006F006E)
    tcp.pokemem(0x00120010, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000048)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000018)
    tcp.pokemem(0x13100079, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x12100079, 0x00000018)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000002B0)
    tcp.pokemem(0x00120000, 0x00430075)
    tcp.pokemem(0x00120004, 0x00730074)
    tcp.pokemem(0x00120008, 0x006F006D)
    tcp.pokemem(0x0012000C, 0x0050006F)
    tcp.pokemem(0x00120010, 0x00740069)
    tcp.pokemem(0x00120014, 0x006F006E)
    tcp.pokemem(0x00120018, 0x00450066)
    tcp.pokemem(0x0012001C, 0x00660065)
    tcp.pokemem(0x00120020, 0x00630074)
    tcp.pokemem(0x00120024, 0x00730000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000020C)
    tcp.pokemem(0x00120000, 0x00490064)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001D8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000026C)
    tcp.pokemem(0x00120000, 0x0014CCA4)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000088)
    tcp.pokemem(0x00120000, 0x1065993C)
    tcp.pokemem(0x00120004, 0x7FFFFFFF)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000018C)
    tcp.pokemem(0x00120000, 0x00440075)
    tcp.pokemem(0x00120004, 0x00720061)
    tcp.pokemem(0x00120008, 0x00740069)
    tcp.pokemem(0x0012000C, 0x006F006E)
    tcp.pokemem(0x00120010, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000004C)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000018)
    tcp.pokemem(0x1310007A, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x1210007A, 0x00000018)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000002B0)
    tcp.pokemem(0x00120000, 0x00430075)
    tcp.pokemem(0x00120004, 0x00730074)
    tcp.pokemem(0x00120008, 0x006F006D)
    tcp.pokemem(0x0012000C, 0x0050006F)
    tcp.pokemem(0x00120010, 0x00740069)
    tcp.pokemem(0x00120014, 0x006F006E)
    tcp.pokemem(0x00120018, 0x00450066)
    tcp.pokemem(0x0012001C, 0x00660065)
    tcp.pokemem(0x00120020, 0x00630074)
    tcp.pokemem(0x00120024, 0x00730000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000020C)
    tcp.pokemem(0x00120000, 0x00490064)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000088)
    tcp.pokemem(0x00120000, 0x1065993C)
    tcp.pokemem(0x00120004, 0x7FFFFFFF)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001DC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000026C)
    tcp.pokemem(0x00120000, 0x0003CCA4)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000018C)
    tcp.pokemem(0x00120000, 0x00440075)
    tcp.pokemem(0x00120004, 0x00720061)
    tcp.pokemem(0x00120008, 0x00740069)
    tcp.pokemem(0x0012000C, 0x006F006E)
    tcp.pokemem(0x00120010, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000050)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000018)
    tcp.pokemem(0x1310007B, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001EC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x1210007B, 0x00000018)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001EC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000002B0)
    tcp.pokemem(0x00120000, 0x00430075)
    tcp.pokemem(0x00120004, 0x00730074)
    tcp.pokemem(0x00120008, 0x006F006D)
    tcp.pokemem(0x0012000C, 0x0050006F)
    tcp.pokemem(0x00120010, 0x00740069)
    tcp.pokemem(0x00120014, 0x006F006E)
    tcp.pokemem(0x00120018, 0x00450066)
    tcp.pokemem(0x0012001C, 0x00660065)
    tcp.pokemem(0x00120020, 0x00630074)
    tcp.pokemem(0x00120024, 0x00730000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001EC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000020C)
    tcp.pokemem(0x00120000, 0x00490064)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000088)
    tcp.pokemem(0x00120000, 0x1065993C)
    tcp.pokemem(0x00120004, 0x7FFFFFFF)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000026C)
    tcp.pokemem(0x00120000, 0x0017CCA4)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001EC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000018C)
    tcp.pokemem(0x00120000, 0x00440075)
    tcp.pokemem(0x00120004, 0x00720061)
    tcp.pokemem(0x00120008, 0x00740069)
    tcp.pokemem(0x0012000C, 0x006F006E)
    tcp.pokemem(0x00120010, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000054)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000018)
    tcp.pokemem(0x1310007C, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001F0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x1210007C, 0x00000018)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001F0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000002B0)
    tcp.pokemem(0x00120000, 0x00430075)
    tcp.pokemem(0x00120004, 0x00730074)
    tcp.pokemem(0x00120008, 0x006F006D)
    tcp.pokemem(0x0012000C, 0x0050006F)
    tcp.pokemem(0x00120010, 0x00740069)
    tcp.pokemem(0x00120014, 0x006F006E)
    tcp.pokemem(0x00120018, 0x00450066)
    tcp.pokemem(0x0012001C, 0x00660065)
    tcp.pokemem(0x00120020, 0x00630074)
    tcp.pokemem(0x00120024, 0x00730000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001F0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000020C)
    tcp.pokemem(0x00120000, 0x00490064)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001EC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000088)
    tcp.pokemem(0x00120000, 0x1065993C)
    tcp.pokemem(0x00120004, 0x7FFFFFFF)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000026C)
    tcp.pokemem(0x00120000, 0x0016CCA4)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001F0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000018C)
    tcp.pokemem(0x00120000, 0x00440075)
    tcp.pokemem(0x00120004, 0x00720061)
    tcp.pokemem(0x00120008, 0x00740069)
    tcp.pokemem(0x0012000C, 0x006F006E)
    tcp.pokemem(0x00120010, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000058)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000018)
    tcp.pokemem(0x1310007D, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001F4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x1210007D, 0x00000018)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001F4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000002B0)
    tcp.pokemem(0x00120000, 0x00430075)
    tcp.pokemem(0x00120004, 0x00730074)
    tcp.pokemem(0x00120008, 0x006F006D)
    tcp.pokemem(0x0012000C, 0x0050006F)
    tcp.pokemem(0x00120010, 0x00740069)
    tcp.pokemem(0x00120014, 0x006F006E)
    tcp.pokemem(0x00120018, 0x00450066)
    tcp.pokemem(0x0012001C, 0x00660065)
    tcp.pokemem(0x00120020, 0x00630074)
    tcp.pokemem(0x00120024, 0x00730000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001F4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000020C)
    tcp.pokemem(0x00120000, 0x00490064)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001F0)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000088)
    tcp.pokemem(0x00120000, 0x1065993C)
    tcp.pokemem(0x00120004, 0x7FFFFFFF)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001E8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000026C)
    tcp.pokemem(0x00120000, 0x0010CCA4)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001F4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000018C)
    tcp.pokemem(0x00120000, 0x00440075)
    tcp.pokemem(0x00120004, 0x00720061)
    tcp.pokemem(0x00120008, 0x00740069)
    tcp.pokemem(0x0012000C, 0x006F006E)
    tcp.pokemem(0x00120010, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000060)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000018)
    tcp.pokemem(0x1310007E, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001F8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x1210007E, 0x00000018)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001F8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000002B0)
    tcp.pokemem(0x00120000, 0x00430075)
    tcp.pokemem(0x00120004, 0x00730074)
    tcp.pokemem(0x00120008, 0x006F006D)
    tcp.pokemem(0x0012000C, 0x0050006F)
    tcp.pokemem(0x00120010, 0x00740069)
    tcp.pokemem(0x00120014, 0x006F006E)
    tcp.pokemem(0x00120018, 0x00450066)
    tcp.pokemem(0x0012001C, 0x00660065)
    tcp.pokemem(0x00120020, 0x00630074)
    tcp.pokemem(0x00120024, 0x00730000)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001F8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000020C)
    tcp.pokemem(0x00120000, 0x00490064)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001F4)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000088)
    tcp.pokemem(0x00120000, 0x1065993C)
    tcp.pokemem(0x00120004, 0x7FFFFFFF)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001EC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000026C)
    tcp.pokemem(0x00120000, 0x0013CCA4)
    tcp.pokemem(0x30000000, 0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001F8)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000018C)
    tcp.pokemem(0x00120000, 0x00440075)
    tcp.pokemem(0x00120004, 0x00720061)
    tcp.pokemem(0x00120008, 0x00740069)
    tcp.pokemem(0x0012000C, 0x006F006E)
    tcp.pokemem(0x00120010, 0x00000000)
    tcp.pokemem(0x30000000, 0x10A0A770)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x0000005C)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x00000018)
    tcp.pokemem(0x1310007F, 0x00000000)
    tcp.pokemem(0x30000000,0x10A0A720)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x31000000, 0x000001FC)
    tcp.pokemem(0x30100000, 0x00000000)
    tcp.pokemem(0x10000000, 0x50000000)
    tcp.pokemem(0x1210007F, 0x00000018)
    tcp.pokemem(0xD0000000,0xDEADCAFE)
    print("pot!")



        
def multiJump():
    if cb7.get() == 1:

        tcp.pokemem(0x0232F3A0, 0x38800001)

        print("Multi-Jump is now active!")
        
    elif cb7.get() == 12:

        tcp.pokemem(0x0232F3A0, 0x38800000)

        print("Multi-Jump disabled!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def muteMic():
    if cb8.get() == 1:

        tcp.pokemem(0x10997EA8, 0x30000000)

        print("Your mic is now muted!")
        
    elif cb8.get() == 14:

        tcp.pokemem(0x10997EA8, 0x3F000000)

        print("Mute mic disabled!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def reach():
    if cb9.get() == 15:

        tcp.pokemem(0x108C9C20, 0x50090000)

        print("Reach = 3 blocks")
        
    elif cb9.get() == 16:

        tcp.pokemem(0x108C9C20, 0x40080000)

        print("reach disabled")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def keyboard():
    if cb10.get() == 17:

        tcp.pokemem(0x02F88110, 0x39400002)
        tcp.pokemem(0x02FAF4F0, 0x39400002)
        tcp.pokemem(0x02FAF560, 0x39400002)
        tcp.pokemem(0x02FAF5DC, 0x39400002)
        tcp.pokemem(0x02FAF64C, 0x39400002)

        print("The entire keyboard is now unlocked!")
        
    elif cb10.get() == 18:

        tcp.pokemem(0x02F88110, 0x39400003)
        tcp.pokemem(0x02FAF4F0, 0x39400003)
        tcp.pokemem(0x02FAF560, 0x39400003)
        tcp.pokemem(0x02FAF5DC, 0x39400003)
        tcp.pokemem(0x02FAF64C, 0x39400003)

        print("Keyboard locked!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def FOV():
    if cb11.get() == 1:

        tcp.pokemem(0x1088EDA8, 0x3F800000)

        print("FOV Enhanced")

def blind():
    if cb26.get() == 1:

        tcp.pokemem(0x1088EDA8, 0xfFffffff)

        print("haha blind")
        

        
def Hitbox():
    if cb12.get() == 12:

        tcp.pokemem(0x030FA0C8, 0xFFFFFFFF)
        tcp.pokemem(0x030FA014, 0x2C090001)
        tcp.pokemem(0x030F9C50, 0xFFFFFFFF)

        print("Hitbox now shown!")
        
    elif cb12.get() == 22:

        tcp.pokemem(0x030FA0C8, 0xFFFFFFFF)
        tcp.pokemem(0x030FA014, 0x2C090001)
        tcp.pokemem(0x030F9C50, 0xFFFFFFFF)

        print("Hitbox now shown!")
        canv = Tk()
        canv.title('Disabling for this code has not yet been added.')
        canv.geometry('200x40')
        btn = Button(canv, text="                           OK!                           ", bd='5', bg="black",                         fg="white",command=canv.destroy)
        btn.pack(side='top')
        canv.mainloop()
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def itemJava():
    if cb13.get() == 23:

        tcp.pokemem(0x0316760C, 0x60000000)
        tcp.pokemem(0x0316762C, 0xFC80F090)
        tcp.pokemem(0x03168DCC, 0xEC4F6BFA)
        tcp.pokemem(0x0384CEBC, 0x3D801002)
        tcp.pokemem(0x0384CEC0, 0x3C40433A)
        tcp.pokemem(0x0384CEC4, 0x904C0110)
        tcp.pokemem(0x0384CEC8, 0xC02C0110)
        tcp.pokemem(0x0384CECC, 0x4B91A770)
        tcp.pokemem(0x03167638, 0x486E5884)

        print("Item Drop animation has now been modified!")
        
    elif cb13.get() == 24:

        tcp.pokemem(0x0316760C, 0x60000000)
        tcp.pokemem(0x0316762C, 0xFC80F090)
        tcp.pokemem(0x03168DCC, 0xEC4F6BFA)
        tcp.pokemem(0x0384CEBC, 0x3D801002)
        tcp.pokemem(0x0384CEC0, 0x3C40433A)
        tcp.pokemem(0x0384CEC4, 0x904C0110)
        tcp.pokemem(0x0384CEC8, 0xC02C0110)
        tcp.pokemem(0x0384CECC, 0x4B91A770)
        tcp.pokemem(0x03167638, 0x486E5884)

        print("Disabling for this code has not yet been added.")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def offhand():
    if cb14.get() == 25:

        tcp.pokemem(0x024FD7F4, 0x38600001)
        tcp.pokemem(0x0207F604, 0x38600001)

        print("All item slots have been unlocked! (eg offhand and body slots)")
        
    elif cb14.get() == 26:

        tcp.pokemem(0x024FD7F4, 0x38600000)
        tcp.pokemem(0x0207F604, 0x38600000)

        print("Item slots back to normal")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def takeAll():
    if cb15.get() == 27:

        tcp.pokemem(0x02DEC0B4, 0x38600001)

        print("You can now take everything from chests!")
        
    elif cb15.get() == 28:

        tcp.pokemem(0x02DEC0B4, 0x57E3063E)

        print("You can no longer take everything")
        canv = Tk()
        canv.title('Code Disabled')
        canv.geometry('200x40')
        btn = Button(canv, text="                           OK!                           ", bd='5', bg="black",                         fg="white",command=canv.destroy)
        btn.pack(side='top')
        canv.mainloop()
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def noclip():
    if cb16.get() == 1:

        tcp.pokemem(0x0232E644, 0xFFFFFFFF)

        print("No-ClIP_Addr is now active!")
        
    elif cb16.get() == 0:

        tcp.pokemem(0x0232E644, 0xFC20F890)

        print("No-ClIP_Addr disabled!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def riptidePunch():
    if cb17.get() == 1:

        tcp.pokemem(0x031F5484, 0x88630390)

        print("RIP_Addrtide Punch is now active!")
        
    elif cb17.get() == 0:

        tcp.pokemem(0x031F5484, 0x88630A08)

        print("RIP_Addrtide Punch disabled!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def riptideAnywhere():
    if cb18.get() == 1:

        tcp.pokemem(0x0232C210, 0x38600001)

        print("RIP_Addrtide Punch is now active!")
        
    elif cb18.get() == 0:

        tcp.pokemem(0x0232C210, 0x38600000)

        print("RIP_Addrtide Punch disabled!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def rodDMG():
    if cb19.get() == 1:

        tcp.pokemem(0x10610AB8, 0x3F800000)

        print("Rods now do damage!")
        
    elif cb19.get() == 0:

        tcp.pokemem(0x10610AB8, 0x3F800000)

        print("Rods no longer do damage!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def explosiveArrows():
    if cb20.get() == 1:

        tcp.pokemem(0x020063F0, 0x487E23A4)

        print("Arrows and tridnets now explode!")
        
    elif cb20.get() == 0:

        tcp.pokemem(0x020063F0, 0x7C0802A6)

        print("Arrows and tridnets no longer explode!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def Speed():
    if cb21.get() == 1:

        tcp.pokemem(0x1066AAE8, 0x3F76F5C3)
        tcp.pokemem(0x1066879C, 0x3DF5C28F)
        tcp.pokemem(0x1066ACC8, 0x3EB9BD1F)

        print("You are on speed!")
        
    elif cb21.get() == 0:

        tcp.pokemem(0x1066AAE8, 0x3F68F5C3)
        tcp.pokemem(0x1066879C, 0x3CA3D70A)
        tcp.pokemem(0x1066ACC8, 0x3E26AD89)

        print("You no longer have speed!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def antiKB():
    if cb22.get() == 1:

        tcp.pokemem(0x0257D85C, 0x4E800020)

        print("You no longer take KnockBack!")
        
    elif cb22.get() == 0:

        tcp.pokemem(0x0257D85C, 0x9421FFA8)

        print("You now take KnockBack")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def allPerms():
    if cb22.get() == 1:

        tcp.pokemem(0x02C57E94, 0x38600001)
        tcp.pokemem(0x02C57E34, 0x38600001)
        tcp.pokemem(0x02C51C20, 0x38600001)
        tcp.pokemem(0x02C5CC84, 0x38600001)
        tcp.pokemem(0x02C57D74, 0x38600001)
        tcp.pokemem(0x02C57DD4, 0x38600001)

        print("All perms now activated!")
        
    elif cb22.get() == 0:

        tcp.pokemem(0x02C57E94, 0x57E3063E)
        tcp.pokemem(0x02C57E34, 0x57E3063E)
        tcp.pokemem(0x02C51C20, 0x57E3063E)
        tcp.pokemem(0x02C5CC84, 0x88630124)
        tcp.pokemem(0x02C57D74, 0x57E3063E)
        tcp.pokemem(0x02C57DD4, 0x57E3063E)

        print("You no longer have all perms!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def craft():
    if cb24.get() == 1:

        tcp.pokemem(0x02F70970, 0x38600001)  
    tcp.pokemem(0x032283CC, 0x38800000)
    tcp.pokemem(0x02F59534, 0x480002E8)

    print("craft ye all!")
                
def lockServer():
    if cb25.get() == 1:

        tcp.pokemem(0x02D5B28C, 0x3BC00001)

        print("Your server is now locked!")
        
    elif cb25.get() == 0:

        tcp.pokemem(0x02D5B28C, 0x3BC00008)

        print("Server unlocked!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
#===== Section: Defined Functions End =====

#===== Section: Tab 2 Defined Function ====

def lvl1():
    if cg.get() == 1:

        tcp.pokemem(0x105DD948, 0x3F100000)

        print("Aura Lvl 1 is now active")
        
    elif cg.get() == 0:

        tcp.pokemem(0x105DD948, 0x3F000000)

        print("Aura reset!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def lvl2():
    if cg2.get() == 2:

        tcp.pokemem(0x105DD948, 0x3F200000)

        print("Aura Lvl 2 is now active")
        
    elif cg2.get() == 3:

        tcp.pokemem(0x105DD948, 0x3F000000)

        print("Aura reset!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def lvl3():
    if cg3.get() == 4:

        tcp.pokemem(0x105DD948, 0x3F300000)

        print("Aura Lvl 3 is now active")
        
    elif cg3.get() == 5:

        tcp.pokemem(0x105DD948, 0x3F000000)

        print("Aura reset!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def lvl4():
    if cg4.get() == 6:

        tcp.pokemem(0x105DD948, 0x3F400000)

        print("Aura Lvl 4 is now active")
        
    elif cg4.get() == 7:

        tcp.pokemem(0x105DD948, 0x3F000000)

        print("Aura reset!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def lvl5():
    if cg5.get() == 8:

        tcp.pokemem(0x105DD948, 0x3F500000)

        print("Aura Lvl 5 is now active")
        
    elif cg5.get() == 9:

        tcp.pokemem(0x105DD948, 0x3F000000)

        print("Aura reset!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def lvl6():
    if cg6.get() == 10:

        tcp.pokemem(0x105DD948, 0x3F600000)

        print("Aura Lvl 6 is now active")
        
    elif cg6.get() == 11:

        tcp.pokemem(0x105DD948, 0x3F000000)

        print("Aura reset!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def lvl7():
    if cg7.get() == 12:

        tcp.pokemem(0x105DD948, 0x3F700000)

        print("Aura Lvl 7 is now active")
        
    elif cg7.get() == 13:

        tcp.pokemem(0x105DD948, 0x3F000000)

        print("Aura reset!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def lvl8():
    if cg8.get() == 14:

        tcp.pokemem(0x105DD948, 0x3F800000)

        print("Aura Lvl 8 is now active")
        
    elif cg8.get() == 15:

        tcp.pokemem(0x105DD948, 0x3F000000)

        print("Aura reset!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def lvl9():
    if cg9.get() == 16:

        tcp.pokemem(0x105DD948, 0x3FF00000)

        print("In the words of 9 year olds: You're a hackowr")
        
    elif cg9.get() == 17:

        tcp.pokemem(0x105DD948, 0x3F000000)

        print("Aura reset!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)
        
def lvl10():
    if cg10.get() == 18:

        tcp.pokemem(0x105DD948, 0x41099999)

        print("I think you just became god")
        
    elif cg10.get() == 19:

        tcp.pokemem(0x105DD948, 0x3F000000)

        print("Aura reset!")
        
    else:
        canv = Tk()
        canv.title('Error!')
        canv.geometry('200x40')
        btn = Button(canv, text = "ERROR!", bd='5', bg="black",                      fg="white",command=canv.destroy)

def test():
    if cb27.get() == 1:

        tcp.readmem(0x10610AB8, 0x3F800000)

def chest_esp():
    if cb27.get() == 1:

        tcp.pokemem(0x04200000, 0x9421FDF8)
    tcp.pokemem(0x04200004, 0x7C0802A6)
    tcp.pokemem(0x04200008, 0x9001020C)
    tcp.pokemem(0x0420000C, 0x92C101B8)
    tcp.pokemem(0x04200010, 0x92E101BC)
    tcp.pokemem(0x04200014, 0x930101C0)
    tcp.pokemem(0x04200018, 0x932101C4)
    tcp.pokemem(0x0420001C, 0x934101C8)
    tcp.pokemem(0x04200020, 0x936101CC)
    tcp.pokemem(0x04200024, 0x938101D0)
    tcp.pokemem(0x04200028, 0x93A101D4)
    tcp.pokemem(0x0420002C, 0x93C101D8)
    tcp.pokemem(0x04200030, 0x93E101DC)
    tcp.pokemem(0x04200034, 0xDBA101F0)
    tcp.pokemem(0x04200038, 0xDBC101F8)
    tcp.pokemem(0x0420003C, 0xDBE10200)
    tcp.pokemem(0x04200040, 0xFFA00890)
    tcp.pokemem(0x04200044, 0xFFC01090)
    tcp.pokemem(0x04200048, 0xFFE01890)
    tcp.pokemem(0x0420004C, 0x3F003F00)
    tcp.pokemem(0x04200050, 0x3F8002FD)
    tcp.pokemem(0x04200054, 0x63991FB4)
    tcp.pokemem(0x04200058, 0x639A2288)
    tcp.pokemem(0x0420005C, 0x639B36C4)
    tcp.pokemem(0x04200060, 0x639C2A34)
    tcp.pokemem(0x04200064, 0x3FA03F80)
    tcp.pokemem(0x04200068, 0x3FC00316)
    tcp.pokemem(0x0420006C, 0x63DE6818)
    tcp.pokemem(0x04200070, 0x7FC903A6)
    tcp.pokemem(0x04200074, 0x4E800421)
    tcp.pokemem(0x04200078, 0x82E30034)
    tcp.pokemem(0x0420007C, 0x3D20030F)
    tcp.pokemem(0x04200080, 0x6129974C)
    tcp.pokemem(0x04200084, 0x7D2903A6)
    tcp.pokemem(0x04200088, 0x4E800421)
    tcp.pokemem(0x0420008C, 0x3D20030E)
    tcp.pokemem(0x04200090, 0x61294B24)
    tcp.pokemem(0x04200094, 0x7D2903A6)
    tcp.pokemem(0x04200098, 0x4E800421)
    tcp.pokemem(0x0420009C, 0x3D20030E)
    tcp.pokemem(0x042000A0, 0x61299B9C)
    tcp.pokemem(0x042000A4, 0x7D2903A6)
    tcp.pokemem(0x042000A8, 0x4E800421)
    tcp.pokemem(0x042000AC, 0x3D20030E)
    tcp.pokemem(0x042000B0, 0x61296268)
    tcp.pokemem(0x042000B4, 0x7D2903A6)
    tcp.pokemem(0x042000B8, 0x4E800421)
    tcp.pokemem(0x042000BC, 0x3D20030E)
    tcp.pokemem(0x042000C0, 0x61295284)
    tcp.pokemem(0x042000C4, 0x7D2903A6)
    tcp.pokemem(0x042000C8, 0x4E800421)
    tcp.pokemem(0x042000CC, 0x38800005)
    tcp.pokemem(0x042000D0, 0x38600004)
    tcp.pokemem(0x042000D4, 0x3D20030E)
    tcp.pokemem(0x042000D8, 0x612952A0)
    tcp.pokemem(0x042000DC, 0x7D2903A6)
    tcp.pokemem(0x042000E0, 0x4E800421)
    tcp.pokemem(0x042000E4, 0x3D200333)
    tcp.pokemem(0x042000E8, 0x61297EF0)
    tcp.pokemem(0x042000EC, 0x7D2903A6)
    tcp.pokemem(0x042000F0, 0x4E800421)
    tcp.pokemem(0x042000F4, 0x80630000)
    tcp.pokemem(0x042000F8, 0x7C7F1B78)
    tcp.pokemem(0x042000FC, 0x7FC903A6)
    tcp.pokemem(0x04200100, 0x4E800421)
    tcp.pokemem(0x04200104, 0x82C30104)
    tcp.pokemem(0x04200108, 0x3D20030E)
    tcp.pokemem(0x0420010C, 0x61294B3C)
    tcp.pokemem(0x04200110, 0x7D2903A6)
    tcp.pokemem(0x04200114, 0x4E800421)
    tcp.pokemem(0x04200118, 0x38800004)
    tcp.pokemem(0x0420011C, 0x7FE3FB78)
    tcp.pokemem(0x04200120, 0x7F2903A6)
    tcp.pokemem(0x04200124, 0x4E800421)
    tcp.pokemem(0x04200128, 0x38A000FF)
    tcp.pokemem(0x0420012C, 0x3C8000FF)
    tcp.pokemem(0x04200130, 0x7FE3FB78)
    tcp.pokemem(0x04200134, 0x7F6903A6)
    tcp.pokemem(0x04200138, 0x4E800421)
    tcp.pokemem(0x0420013C, 0x93010070)
    tcp.pokemem(0x04200140, 0x7FE3FB78)
    tcp.pokemem(0x04200144, 0xC0210070)
    tcp.pokemem(0x04200148, 0x93010074)
    tcp.pokemem(0x0420014C, 0xEC3D082A)
    tcp.pokemem(0x04200150, 0xC0410074)
    tcp.pokemem(0x04200154, 0x93010078)
    tcp.pokemem(0x04200158, 0xEC5E102A)
    tcp.pokemem(0x0420015C, 0xC0610078)
    tcp.pokemem(0x04200160, 0xEC7F182A)
    tcp.pokemem(0x04200164, 0x7F8903A6)
    tcp.pokemem(0x04200168, 0x4E800421)
    tcp.pokemem(0x0420016C, 0x38A000FF)
    tcp.pokemem(0x04200170, 0x388000FF)
    tcp.pokemem(0x04200174, 0x7FE3FB78)
    tcp.pokemem(0x04200178, 0x7F6903A6)
    tcp.pokemem(0x0420017C, 0x4E800421)
    tcp.pokemem(0x04200180, 0x3BC00000)
    tcp.pokemem(0x04200184, 0x93C1007C)
    tcp.pokemem(0x04200188, 0x93C10080)
    tcp.pokemem(0x0420018C, 0x93C10084)
    tcp.pokemem(0x04200190, 0xC021007C)
    tcp.pokemem(0x04200194, 0xC0410080)
    tcp.pokemem(0x04200198, 0xC0610084)
    tcp.pokemem(0x0420019C, 0x7FE3FB78)
    tcp.pokemem(0x042001A0, 0x7F8903A6)
    tcp.pokemem(0x042001A4, 0x4E800421)
    tcp.pokemem(0x042001A8, 0x7FE3FB78)
    tcp.pokemem(0x042001AC, 0x7F4903A6)
    tcp.pokemem(0x042001B0, 0x4E800421)
    tcp.pokemem(0x042001B4, 0x7FE3FB78)
    tcp.pokemem(0x042001B8, 0x38800003)
    tcp.pokemem(0x042001BC, 0x7F2903A6)
    tcp.pokemem(0x042001C0, 0x4E800421)
    tcp.pokemem(0x042001C4, 0x38A0001E)
    tcp.pokemem(0x042001C8, 0x3C8000FF)
    tcp.pokemem(0x042001CC, 0x7FE3FB78)
    tcp.pokemem(0x042001D0, 0x7F6903A6)
    tcp.pokemem(0x042001D4, 0x4E800421)
    tcp.pokemem(0x042001D8, 0x93C10088)
    tcp.pokemem(0x042001DC, 0x7FE3FB78)
    tcp.pokemem(0x042001E0, 0x7F8903A6)
    tcp.pokemem(0x042001E4, 0xC0210088)
    tcp.pokemem(0x042001E8, 0x93C1008C)
    tcp.pokemem(0x042001EC, 0xEC3D082A)
    tcp.pokemem(0x042001F0, 0xC041008C)
    tcp.pokemem(0x042001F4, 0x93C10090)
    tcp.pokemem(0x042001F8, 0xEC5E102A)
    tcp.pokemem(0x042001FC, 0xC0610090)
    tcp.pokemem(0x04200200, 0xEC7F182A)
    tcp.pokemem(0x04200204, 0x4E800421)
    tcp.pokemem(0x04200208, 0x93A10094)
    tcp.pokemem(0x0420020C, 0x7FE3FB78)
    tcp.pokemem(0x04200210, 0x7F8903A6)
    tcp.pokemem(0x04200214, 0xC0210094)
    tcp.pokemem(0x04200218, 0x93C10098)
    tcp.pokemem(0x0420021C, 0xEC3D082A)
    tcp.pokemem(0x04200220, 0xC0410098)
    tcp.pokemem(0x04200224, 0x93C1009C)
    tcp.pokemem(0x04200228, 0xEC5E102A)
    tcp.pokemem(0x0420022C, 0xC061009C)
    tcp.pokemem(0x04200230, 0xEC7F182A)
    tcp.pokemem(0x04200234, 0x4E800421)
    tcp.pokemem(0x04200238, 0x93A100A0)
    tcp.pokemem(0x0420023C, 0x7FE3FB78)
    tcp.pokemem(0x04200240, 0xC02100A0)
    tcp.pokemem(0x04200244, 0x93A100A4)
    tcp.pokemem(0x04200248, 0xEC3D082A)
    tcp.pokemem(0x0420024C, 0xC04100A4)
    tcp.pokemem(0x04200250, 0x93C100A8)
    tcp.pokemem(0x04200254, 0xEC5E102A)
    tcp.pokemem(0x04200258, 0xC06100A8)
    tcp.pokemem(0x0420025C, 0xEC7F182A)
    tcp.pokemem(0x04200260, 0x7F8903A6)
    tcp.pokemem(0x04200264, 0x4E800421)
    tcp.pokemem(0x04200268, 0x93C100AC)
    tcp.pokemem(0x0420026C, 0x7FE3FB78)
    tcp.pokemem(0x04200270, 0xC02100AC)
    tcp.pokemem(0x04200274, 0x93A100B0)
    tcp.pokemem(0x04200278, 0xEC3D082A)
    tcp.pokemem(0x0420027C, 0xC04100B0)
    tcp.pokemem(0x04200280, 0x93C100B4)
    tcp.pokemem(0x04200284, 0xEC5E102A)
    tcp.pokemem(0x04200288, 0xC06100B4)
    tcp.pokemem(0x0420028C, 0xEC7F182A)
    tcp.pokemem(0x04200290, 0x7F8903A6)
    tcp.pokemem(0x04200294, 0x4E800421)
    tcp.pokemem(0x04200298, 0x7FE3FB78)
    tcp.pokemem(0x0420029C, 0x7F4903A6)
    tcp.pokemem(0x042002A0, 0x4E800421)
    tcp.pokemem(0x042002A4, 0x7FE3FB78)
    tcp.pokemem(0x042002A8, 0x38800003)
    tcp.pokemem(0x042002AC, 0x7F2903A6)
    tcp.pokemem(0x042002B0, 0x4E800421)
    tcp.pokemem(0x042002B4, 0x38A0001E)
    tcp.pokemem(0x042002B8, 0x3C8000FF)
    tcp.pokemem(0x042002BC, 0x7FE3FB78)
    tcp.pokemem(0x042002C0, 0x7F6903A6)
    tcp.pokemem(0x042002C4, 0x4E800421)
    tcp.pokemem(0x042002C8, 0x93C100B8)
    tcp.pokemem(0x042002CC, 0x7FE3FB78)
    tcp.pokemem(0x042002D0, 0x7F8903A6)
    tcp.pokemem(0x042002D4, 0xC02100B8)
    tcp.pokemem(0x042002D8, 0x93C100BC)
    tcp.pokemem(0x042002DC, 0xEC3D082A)
    tcp.pokemem(0x042002E0, 0xC04100BC)
    tcp.pokemem(0x042002E4, 0x93A100C0)
    tcp.pokemem(0x042002E8, 0xEC5E102A)
    tcp.pokemem(0x042002EC, 0xC06100C0)
    tcp.pokemem(0x042002F0, 0xEC7F182A)
    tcp.pokemem(0x042002F4, 0x4E800421)
    tcp.pokemem(0x042002F8, 0x93A100C4)
    tcp.pokemem(0x042002FC, 0x7FE3FB78)
    tcp.pokemem(0x04200300, 0x7F8903A6)
    tcp.pokemem(0x04200304, 0xC02100C4)
    tcp.pokemem(0x04200308, 0x93C100C8)
    tcp.pokemem(0x0420030C, 0xEC3D082A)
    tcp.pokemem(0x04200310, 0xC04100C8)
    tcp.pokemem(0x04200314, 0x93A100CC)
    tcp.pokemem(0x04200318, 0xEC5E102A)
    tcp.pokemem(0x0420031C, 0xC06100CC)
    tcp.pokemem(0x04200320, 0xEC7F182A)
    tcp.pokemem(0x04200324, 0x4E800421)
    tcp.pokemem(0x04200328, 0x93A100D0)
    tcp.pokemem(0x0420032C, 0x7FE3FB78)
    tcp.pokemem(0x04200330, 0x7F8903A6)
    tcp.pokemem(0x04200334, 0xC02100D0)
    tcp.pokemem(0x04200338, 0x93A100D4)
    tcp.pokemem(0x0420033C, 0xEC3D082A)
    tcp.pokemem(0x04200340, 0xC04100D4)
    tcp.pokemem(0x04200344, 0x93A100D8)
    tcp.pokemem(0x04200348, 0xEC5E102A)
    tcp.pokemem(0x0420034C, 0xC06100D8)
    tcp.pokemem(0x04200350, 0xEC7F182A)
    tcp.pokemem(0x04200354, 0x4E800421)
    tcp.pokemem(0x04200358, 0x93C100DC)
    tcp.pokemem(0x0420035C, 0x7FE3FB78)
    tcp.pokemem(0x04200360, 0x7F8903A6)
    tcp.pokemem(0x04200364, 0xC02100DC)
    tcp.pokemem(0x04200368, 0x93A100E0)
    tcp.pokemem(0x0420036C, 0xEC3D082A)
    tcp.pokemem(0x04200370, 0xC04100E0)
    tcp.pokemem(0x04200374, 0x93A100E4)
    tcp.pokemem(0x04200378, 0xEC5E102A)
    tcp.pokemem(0x0420037C, 0xC06100E4)
    tcp.pokemem(0x04200380, 0xEC7F182A)
    tcp.pokemem(0x04200384, 0x4E800421)
    tcp.pokemem(0x04200388, 0x7FE3FB78)
    tcp.pokemem(0x0420038C, 0x7F4903A6)
    tcp.pokemem(0x04200390, 0x4E800421)
    tcp.pokemem(0x04200394, 0x7FE3FB78)
    tcp.pokemem(0x04200398, 0x38800003)
    tcp.pokemem(0x0420039C, 0x7F2903A6)
    tcp.pokemem(0x042003A0, 0x4E800421)
    tcp.pokemem(0x042003A4, 0x38A0001E)
    tcp.pokemem(0x042003A8, 0x3C8000FF)
    tcp.pokemem(0x042003AC, 0x7FE3FB78)
    tcp.pokemem(0x042003B0, 0x7F6903A6)
    tcp.pokemem(0x042003B4, 0x4E800421)
    tcp.pokemem(0x042003B8, 0x93C100E8)
    tcp.pokemem(0x042003BC, 0x7FE3FB78)
    tcp.pokemem(0x042003C0, 0x7F8903A6)
    tcp.pokemem(0x042003C4, 0xC02100E8)
    tcp.pokemem(0x042003C8, 0x93C100EC)
    tcp.pokemem(0x042003CC, 0xEC3D082A)
    tcp.pokemem(0x042003D0, 0xC04100EC)
    tcp.pokemem(0x042003D4, 0x93C100F0)
    tcp.pokemem(0x042003D8, 0xEC5E102A)
    tcp.pokemem(0x042003DC, 0xC06100F0)
    tcp.pokemem(0x042003E0, 0xEC7F182A)
    tcp.pokemem(0x042003E4, 0x4E800421)
    tcp.pokemem(0x042003E8, 0x93C100F4)
    tcp.pokemem(0x042003EC, 0x7FE3FB78)
    tcp.pokemem(0x042003F0, 0x7F8903A6)
    tcp.pokemem(0x042003F4, 0xC02100F4)
    tcp.pokemem(0x042003F8, 0x93A100F8)
    tcp.pokemem(0x042003FC, 0xEC3D082A)
    tcp.pokemem(0x04200400, 0xC04100F8)
    tcp.pokemem(0x04200404, 0x93C100FC)
    tcp.pokemem(0x04200408, 0xEC5E102A)
    tcp.pokemem(0x0420040C, 0xC06100FC)
    tcp.pokemem(0x04200410, 0xEC7F182A)
    tcp.pokemem(0x04200414, 0x4E800421)
    tcp.pokemem(0x04200418, 0x93C10100)
    tcp.pokemem(0x0420041C, 0x7FE3FB78)
    tcp.pokemem(0x04200420, 0x7F8903A6)
    tcp.pokemem(0x04200424, 0xC0210100)
    tcp.pokemem(0x04200428, 0x93A10104)
    tcp.pokemem(0x0420042C, 0xEC3D082A)
    tcp.pokemem(0x04200430, 0xC0410104)
    tcp.pokemem(0x04200434, 0x93A10108)
    tcp.pokemem(0x04200438, 0xEC5E102A)
    tcp.pokemem(0x0420043C, 0xC0610108)
    tcp.pokemem(0x04200440, 0xEC7F182A)
    tcp.pokemem(0x04200444, 0x4E800421)
    tcp.pokemem(0x04200448, 0x93C1010C)
    tcp.pokemem(0x0420044C, 0x7FE3FB78)
    tcp.pokemem(0x04200450, 0x7F8903A6)
    tcp.pokemem(0x04200454, 0xC021010C)
    tcp.pokemem(0x04200458, 0x93C10110)
    tcp.pokemem(0x0420045C, 0xEC3D082A)
    tcp.pokemem(0x04200460, 0xC0410110)
    tcp.pokemem(0x04200464, 0x93A10114)
    tcp.pokemem(0x04200468, 0xEC5E102A)
    tcp.pokemem(0x0420046C, 0xC0610114)
    tcp.pokemem(0x04200470, 0xEC7F182A)
    tcp.pokemem(0x04200474, 0x4E800421)
    tcp.pokemem(0x04200478, 0x7FE3FB78)
    tcp.pokemem(0x0420047C, 0x7F4903A6)
    tcp.pokemem(0x04200480, 0x4E800421)
    tcp.pokemem(0x04200484, 0x7FE3FB78)
    tcp.pokemem(0x04200488, 0x38800003)
    tcp.pokemem(0x0420048C, 0x7F2903A6)
    tcp.pokemem(0x04200490, 0x4E800421)
    tcp.pokemem(0x04200494, 0x38A0001E)
    tcp.pokemem(0x04200498, 0x3C8000FF)
    tcp.pokemem(0x0420049C, 0x7FE3FB78)
    tcp.pokemem(0x042004A0, 0x7F6903A6)
    tcp.pokemem(0x042004A4, 0x4E800421)
    tcp.pokemem(0x042004A8, 0x93A10118)
    tcp.pokemem(0x042004AC, 0x7FE3FB78)
    tcp.pokemem(0x042004B0, 0x7F8903A6)
    tcp.pokemem(0x042004B4, 0xC0210118)
    tcp.pokemem(0x042004B8, 0x93C1011C)
    tcp.pokemem(0x042004BC, 0xEC3D082A)
    tcp.pokemem(0x042004C0, 0xC041011C)
    tcp.pokemem(0x042004C4, 0x93C10120)
    tcp.pokemem(0x042004C8, 0xEC5E102A)
    tcp.pokemem(0x042004CC, 0xC0610120)
    tcp.pokemem(0x042004D0, 0xEC7F182A)
    tcp.pokemem(0x042004D4, 0x4E800421)
    tcp.pokemem(0x042004D8, 0x93A10124)
    tcp.pokemem(0x042004DC, 0x7FE3FB78)
    tcp.pokemem(0x042004E0, 0x7F8903A6)
    tcp.pokemem(0x042004E4, 0xC0210124)
    tcp.pokemem(0x042004E8, 0x93A10128)
    tcp.pokemem(0x042004EC, 0xEC3D082A)
    tcp.pokemem(0x042004F0, 0xC0410128)
    tcp.pokemem(0x042004F4, 0x93C1012C)
    tcp.pokemem(0x042004F8, 0xEC5E102A)
    tcp.pokemem(0x042004FC, 0xC061012C)
    tcp.pokemem(0x04200500, 0xEC7F182A)
    tcp.pokemem(0x04200504, 0x4E800421)
    tcp.pokemem(0x04200508, 0x93A10130)
    tcp.pokemem(0x0420050C, 0x7FE3FB78)
    tcp.pokemem(0x04200510, 0x7F8903A6)
    tcp.pokemem(0x04200514, 0xC0210130)
    tcp.pokemem(0x04200518, 0x93A10134)
    tcp.pokemem(0x0420051C, 0xEC3D082A)
    tcp.pokemem(0x04200520, 0xC0410134)
    tcp.pokemem(0x04200524, 0x93A10138)
    tcp.pokemem(0x04200528, 0xEC5E102A)
    tcp.pokemem(0x0420052C, 0xC0610138)
    tcp.pokemem(0x04200530, 0xEC7F182A)
    tcp.pokemem(0x04200534, 0x4E800421)
    tcp.pokemem(0x04200538, 0x93A1013C)
    tcp.pokemem(0x0420053C, 0x7FE3FB78)
    tcp.pokemem(0x04200540, 0x7F8903A6)
    tcp.pokemem(0x04200544, 0xC021013C)
    tcp.pokemem(0x04200548, 0x93C10140)
    tcp.pokemem(0x0420054C, 0xEC3D082A)
    tcp.pokemem(0x04200550, 0xC0410140)
    tcp.pokemem(0x04200554, 0x93A10144)
    tcp.pokemem(0x04200558, 0xEC5E102A)
    tcp.pokemem(0x0420055C, 0xC0610144)
    tcp.pokemem(0x04200560, 0xEC7F182A)
    tcp.pokemem(0x04200564, 0x4E800421)
    tcp.pokemem(0x04200568, 0x7FE3FB78)
    tcp.pokemem(0x0420056C, 0x7F4903A6)
    tcp.pokemem(0x04200570, 0x4E800421)
    tcp.pokemem(0x04200574, 0x7FE3FB78)
    tcp.pokemem(0x04200578, 0x38800003)
    tcp.pokemem(0x0420057C, 0x7F2903A6)
    tcp.pokemem(0x04200580, 0x4E800421)
    tcp.pokemem(0x04200584, 0x38A0001E)
    tcp.pokemem(0x04200588, 0x3C8000FF)
    tcp.pokemem(0x0420058C, 0x7FE3FB78)
    tcp.pokemem(0x04200590, 0x7F6903A6)
    tcp.pokemem(0x04200594, 0x4E800421)
    tcp.pokemem(0x04200598, 0x93C10148)
    tcp.pokemem(0x0420059C, 0x7FE3FB78)
    tcp.pokemem(0x042005A0, 0xC0210148)
    tcp.pokemem(0x042005A4, 0x93C1014C)
    tcp.pokemem(0x042005A8, 0xEC3D082A)
    tcp.pokemem(0x042005AC, 0xC041014C)
    tcp.pokemem(0x042005B0, 0x93C10150)
    tcp.pokemem(0x042005B4, 0xEC5E102A)
    tcp.pokemem(0x042005B8, 0xC0610150)
    tcp.pokemem(0x042005BC, 0xEC7F182A)
    tcp.pokemem(0x042005C0, 0x7F8903A6)
    tcp.pokemem(0x042005C4, 0x4E800421)
    tcp.pokemem(0x042005C8, 0x93C10154)
    tcp.pokemem(0x042005CC, 0x7FE3FB78)
    tcp.pokemem(0x042005D0, 0xC0210154)
    tcp.pokemem(0x042005D4, 0x93C10158)
    tcp.pokemem(0x042005D8, 0xEC3D082A)
    tcp.pokemem(0x042005DC, 0xC0410158)
    tcp.pokemem(0x042005E0, 0x93A1015C)
    tcp.pokemem(0x042005E4, 0xEC5E102A)
    tcp.pokemem(0x042005E8, 0xC061015C)
    tcp.pokemem(0x042005EC, 0xEC7F182A)
    tcp.pokemem(0x042005F0, 0x7F8903A6)
    tcp.pokemem(0x042005F4, 0x4E800421)
    tcp.pokemem(0x042005F8, 0x93A10160)
    tcp.pokemem(0x042005FC, 0x7FE3FB78)
    tcp.pokemem(0x04200600, 0xC0210160)
    tcp.pokemem(0x04200604, 0x93C10164)
    tcp.pokemem(0x04200608, 0xEC3D082A)
    tcp.pokemem(0x0420060C, 0xC0410164)
    tcp.pokemem(0x04200610, 0x93A10168)
    tcp.pokemem(0x04200614, 0xEC5E102A)
    tcp.pokemem(0x04200618, 0xC0610168)
    tcp.pokemem(0x0420061C, 0xEC7F182A)
    tcp.pokemem(0x04200620, 0x7F8903A6)
    tcp.pokemem(0x04200624, 0x4E800421)
    tcp.pokemem(0x04200628, 0x93A1016C)
    tcp.pokemem(0x0420062C, 0x7FE3FB78)
    tcp.pokemem(0x04200630, 0xC021016C)
    tcp.pokemem(0x04200634, 0x93C10170)
    tcp.pokemem(0x04200638, 0xEC3D082A)
    tcp.pokemem(0x0420063C, 0xC0410170)
    tcp.pokemem(0x04200640, 0x93C10174)
    tcp.pokemem(0x04200644, 0xEC5E102A)
    tcp.pokemem(0x04200648, 0xC0610174)
    tcp.pokemem(0x0420064C, 0xEC7F182A)
    tcp.pokemem(0x04200650, 0x7F8903A6)
    tcp.pokemem(0x04200654, 0x4E800421)
    tcp.pokemem(0x04200658, 0x7FE3FB78)
    tcp.pokemem(0x0420065C, 0x7F4903A6)
    tcp.pokemem(0x04200660, 0x4E800421)
    tcp.pokemem(0x04200664, 0x7FE3FB78)
    tcp.pokemem(0x04200668, 0x38800003)
    tcp.pokemem(0x0420066C, 0x7F2903A6)
    tcp.pokemem(0x04200670, 0x4E800421)
    tcp.pokemem(0x04200674, 0x38A0001E)
    tcp.pokemem(0x04200678, 0x3C8000FF)
    tcp.pokemem(0x0420067C, 0x7FE3FB78)
    tcp.pokemem(0x04200680, 0x7F6903A6)
    tcp.pokemem(0x04200684, 0x4E800421)
    tcp.pokemem(0x04200688, 0x93C10178)
    tcp.pokemem(0x0420068C, 0xC0210178)
    tcp.pokemem(0x04200690, 0xEC3D082A)
    tcp.pokemem(0x04200694, 0x93A1017C)
    tcp.pokemem(0x04200698, 0xC041017C)
    tcp.pokemem(0x0420069C, 0xEC5E102A)
    tcp.pokemem(0x042006A0, 0x93C10180)
    tcp.pokemem(0x042006A4, 0xC0610180)
    tcp.pokemem(0x042006A8, 0xEC7F182A)
    tcp.pokemem(0x042006AC, 0x7FE3FB78)
    tcp.pokemem(0x042006B0, 0x7F8903A6)
    tcp.pokemem(0x042006B4, 0x4E800421)
    tcp.pokemem(0x042006B8, 0x93C10184)
    tcp.pokemem(0x042006BC, 0xC0210184)
    tcp.pokemem(0x042006C0, 0xEC3D082A)
    tcp.pokemem(0x042006C4, 0x93A10188)
    tcp.pokemem(0x042006C8, 0xC0410188)
    tcp.pokemem(0x042006CC, 0xEC5E102A)
    tcp.pokemem(0x042006D0, 0x93A1018C)
    tcp.pokemem(0x042006D4, 0xC061018C)
    tcp.pokemem(0x042006D8, 0xEC7F182A)
    tcp.pokemem(0x042006DC, 0x7FE3FB78)
    tcp.pokemem(0x042006E0, 0x7F8903A6)
    tcp.pokemem(0x042006E4, 0x4E800421)
    tcp.pokemem(0x042006E8, 0x93A10190)
    tcp.pokemem(0x042006EC, 0xC0210190)
    tcp.pokemem(0x042006F0, 0x93A10194)
    tcp.pokemem(0x042006F4, 0xC0410194)
    tcp.pokemem(0x042006F8, 0x93A10198)
    tcp.pokemem(0x042006FC, 0xC0610198)
    tcp.pokemem(0x04200700, 0xEC3D082A)
    tcp.pokemem(0x04200704, 0xEC5E102A)
    tcp.pokemem(0x04200708, 0xEC7F182A)
    tcp.pokemem(0x0420070C, 0x7FE3FB78)
    tcp.pokemem(0x04200710, 0x7F8903A6)
    tcp.pokemem(0x04200714, 0x4E800421)
    tcp.pokemem(0x04200718, 0x93A1019C)
    tcp.pokemem(0x0420071C, 0xC021019C)
    tcp.pokemem(0x04200720, 0x93A101A0)
    tcp.pokemem(0x04200724, 0xC04101A0)
    tcp.pokemem(0x04200728, 0x93C101A4)
    tcp.pokemem(0x0420072C, 0xC06101A4)
    tcp.pokemem(0x04200730, 0xEC3D082A)
    tcp.pokemem(0x04200734, 0xEC5E102A)
    tcp.pokemem(0x04200738, 0xEC7F182A)
    tcp.pokemem(0x0420073C, 0x7FE3FB78)
    tcp.pokemem(0x04200740, 0x7F8903A6)
    tcp.pokemem(0x04200744, 0x4E800421)
    tcp.pokemem(0x04200748, 0x7FE3FB78)
    tcp.pokemem(0x0420074C, 0x7F4903A6)
    tcp.pokemem(0x04200750, 0x4E800421)
    tcp.pokemem(0x04200754, 0xEC3F07F2)
    tcp.pokemem(0x04200758, 0xEC3D0F7A)
    tcp.pokemem(0x0420075C, 0x3FE00383)
    tcp.pokemem(0x04200760, 0x63FF23CC)
    tcp.pokemem(0x04200764, 0x7FE903A6)
    tcp.pokemem(0x04200768, 0x4E800421)
    tcp.pokemem(0x0420076C, 0x3D204040)
    tcp.pokemem(0x04200770, 0x912101A8)
    tcp.pokemem(0x04200774, 0xC00101A8)
    tcp.pokemem(0x04200778, 0xFF800800)
    tcp.pokemem(0x0420077C, 0x409C0134)
    tcp.pokemem(0x04200780, 0xDB6101E0)
    tcp.pokemem(0x04200784, 0xDB8101E8)
    tcp.pokemem(0x04200788, 0x3D20BD4C)
    tcp.pokemem(0x0420078C, 0x6129CCCD)
    tcp.pokemem(0x04200790, 0x91210050)
    tcp.pokemem(0x04200794, 0xC3610050)
    tcp.pokemem(0x04200798, 0xFF800890)
    tcp.pokemem(0x0420079C, 0x7FE903A6)
    tcp.pokemem(0x042007A0, 0x4E800421)
    tcp.pokemem(0x042007A4, 0x93010054)
    tcp.pokemem(0x042007A8, 0xC0010054)
    tcp.pokemem(0x042007AC, 0x3D403FC0)
    tcp.pokemem(0x042007B0, 0x91410058)
    tcp.pokemem(0x042007B4, 0xC0410058)
    tcp.pokemem(0x042007B8, 0xEF6106F2)
    tcp.pokemem(0x042007BC, 0xEC3D002A)
    tcp.pokemem(0x042007C0, 0xEC5E102A)
    tcp.pokemem(0x042007C4, 0x9301005C)
    tcp.pokemem(0x042007C8, 0xC061005C)
    tcp.pokemem(0x042007CC, 0xEC7F182A)
    tcp.pokemem(0x042007D0, 0x3D20030E)
    tcp.pokemem(0x042007D4, 0x61294B54)
    tcp.pokemem(0x042007D8, 0x7D2903A6)
    tcp.pokemem(0x042007DC, 0x4E800421)
    tcp.pokemem(0x042007E0, 0x3D20BF80)
    tcp.pokemem(0x042007E4, 0x91210060)
    tcp.pokemem(0x042007E8, 0xFC20D890)
    tcp.pokemem(0x042007EC, 0xFC40D890)
    tcp.pokemem(0x042007F0, 0xC0610060)
    tcp.pokemem(0x042007F4, 0xEC7B00F2)
    tcp.pokemem(0x042007F8, 0x3D20030E)
    tcp.pokemem(0x042007FC, 0x61294B6C)
    tcp.pokemem(0x04200800, 0x7D2903A6)
    tcp.pokemem(0x04200804, 0x4E800421)
    tcp.pokemem(0x04200808, 0x93C10064)
    tcp.pokemem(0x0420080C, 0xC0370148)
    tcp.pokemem(0x04200810, 0xC0410064)
    tcp.pokemem(0x04200814, 0x93A10068)
    tcp.pokemem(0x04200818, 0xC0610068)
    tcp.pokemem(0x0420081C, 0x93C1006C)
    tcp.pokemem(0x04200820, 0xC081006C)
    tcp.pokemem(0x04200824, 0x3D20030E)
    tcp.pokemem(0x04200828, 0x61294B84)
    tcp.pokemem(0x0420082C, 0x7D2903A6)
    tcp.pokemem(0x04200830, 0x4E800421)
    tcp.pokemem(0x04200834, 0x48000011)
    tcp.pokemem(0x04200838, 0x0025002E)
    tcp.pokemem(0x0420083C, 0x00310066)
    tcp.pokemem(0x04200840, 0x006D0000)
    tcp.pokemem(0x04200844, 0x7CA802A6)
    tcp.pokemem(0x04200848, 0xFC20E090)
    tcp.pokemem(0x0420084C, 0x38800032)
    tcp.pokemem(0x04200850, 0x38610008)
    tcp.pokemem(0x04200854, 0x4CC63242)
    tcp.pokemem(0x04200858, 0x3D200382)
    tcp.pokemem(0x0420085C, 0x6129C8C0)
    tcp.pokemem(0x04200860, 0x7D2903A6)
    tcp.pokemem(0x04200864, 0x4E800421)
    tcp.pokemem(0x04200868, 0x38810008)
    tcp.pokemem(0x0420086C, 0x38610030)
    tcp.pokemem(0x04200870, 0x3D20020B)
    tcp.pokemem(0x04200874, 0x612908D4)
    tcp.pokemem(0x04200878, 0x7D2903A6)
    tcp.pokemem(0x0420087C, 0x4E800421)
    tcp.pokemem(0x04200880, 0x3CE0FFE0)
    tcp.pokemem(0x04200884, 0x38810030)
    tcp.pokemem(0x04200888, 0x7EC3B378)
    tcp.pokemem(0x0420088C, 0x60E7862A)
    tcp.pokemem(0x04200890, 0x38C00000)
    tcp.pokemem(0x04200894, 0x38A00000)
    tcp.pokemem(0x04200898, 0x3D200312)
    tcp.pokemem(0x0420089C, 0x61296B88)
    tcp.pokemem(0x042008A0, 0x7D2903A6)
    tcp.pokemem(0x042008A4, 0x4E800421)
    tcp.pokemem(0x042008A8, 0xCB6101E0)
    tcp.pokemem(0x042008AC, 0xCB8101E8)
    tcp.pokemem(0x042008B0, 0x3D20030E)
    tcp.pokemem(0x042008B4, 0x61294BD8)
    tcp.pokemem(0x042008B8, 0x7D2903A6)
    tcp.pokemem(0x042008BC, 0x4E800421)
    tcp.pokemem(0x042008C0, 0x3D20030E)
    tcp.pokemem(0x042008C4, 0x61296294)
    tcp.pokemem(0x042008C8, 0x7D2903A6)
    tcp.pokemem(0x042008CC, 0x4E800421)
    tcp.pokemem(0x042008D0, 0x3D20030E)
    tcp.pokemem(0x042008D4, 0x61299BB8)
    tcp.pokemem(0x042008D8, 0x7D2903A6)
    tcp.pokemem(0x042008DC, 0x4E800421)
    tcp.pokemem(0x042008E0, 0x3D20030E)
    tcp.pokemem(0x042008E4, 0x61294C04)
    tcp.pokemem(0x042008E8, 0x7D2903A6)
    tcp.pokemem(0x042008EC, 0x4E800421)
    tcp.pokemem(0x042008F0, 0x8001020C)
    tcp.pokemem(0x042008F4, 0x82C101B8)
    tcp.pokemem(0x042008F8, 0x82E101BC)
    tcp.pokemem(0x042008FC, 0x830101C0)
    tcp.pokemem(0x04200900, 0x832101C4)
    tcp.pokemem(0x04200904, 0x834101C8)
    tcp.pokemem(0x04200908, 0x836101CC)
    tcp.pokemem(0x0420090C, 0x838101D0)
    tcp.pokemem(0x04200910, 0x83A101D4)
    tcp.pokemem(0x04200914, 0x83C101D8)
    tcp.pokemem(0x04200918, 0x83E101DC)
    tcp.pokemem(0x0420091C, 0xCBA101F0)
    tcp.pokemem(0x04200920, 0xCBC101F8)
    tcp.pokemem(0x04200924, 0xCBE10200)
    tcp.pokemem(0x04200928, 0x7C0803A6)
    tcp.pokemem(0x0420092C, 0x38210208)
    tcp.pokemem(0x04200930, 0x4E800020)
    tcp.pokemem(0x02FE3224, 0x4E800421)
    tcp.pokemem(0x0384CCE8, 0x4E800421)
    tcp.pokemem(0x0384CCEC, 0x3DA00420)
    tcp.pokemem(0x0384CCF0, 0x7DA903A6)
    tcp.pokemem(0x0384CCF4, 0x4E800421)
    tcp.pokemem(0x0384CCF8, 0x4B796530)
    tcp.pokemem(0x02FE3224, 0x48869AC4)

#===== Section Tab 2 Defined Functions End ====

#===== Section: Tab 2 =====

cb = IntVar()
cb2 = IntVar()
cb3 = IntVar()
cb4 = IntVar()
cb5 = IntVar()
cb6 = IntVar()
cb7 = IntVar()
cb8 = IntVar()
cb9 = IntVar()
cb10 = IntVar()
cb11 = IntVar()
cb12 = IntVar()
cb13 = IntVar()
cb14 = IntVar()
cb15 = IntVar()
cb16 = IntVar()
cb17 = IntVar()
cb18 = IntVar()
cb19 = IntVar()
cb20 = IntVar()
cb21 = IntVar()
cb22 = IntVar()
cb23 = IntVar()
cb24 = IntVar()
cb25 = IntVar()
cb26 = IntVar()
cb27 = IntVar()
cb28 = IntVar()

c = Checkbutton(tab2, text="fly", variable=cb2, onvalue=1, offvalue=0, command=fly2)
c.grid(column=0, row=0)

c = Checkbutton(tab2, text="kickNt2", variable=cb, onvalue=1, offvalue=0, command=kickNt2)
c.grid(column=1, row=0)

c = Checkbutton(tab2, text="Speed", variable=cb21, onvalue=1, offvalue=0, command=Speed)
c.grid(column=0, row=1)

c = Checkbutton(tab2, text="FOV", variable=cb11, onvalue=1, offvalue=0, command=FOV)
c.grid(column=2, row=0)

c = Checkbutton(tab2, text="craft", variable=cb24, onvalue=1, offvalue=0, command=craft)
c.grid(column=1, row=1)

c = Checkbutton(tab2, text="Frn", variable=cb5, onvalue=1, offvalue=0, command=FOFbypass)
c.grid(column=2, row=1)

c = Checkbutton(tab2, text="perm", variable=cb22, onvalue=1, offvalue=0, command=allPerms)
c.grid(column=3, row=0)

c = Checkbutton(tab2, text="wall", variable=cb16, onvalue=1, offvalue=0, command=noclip)
c.grid(column=0, row=3)

c = Checkbutton(tab2, text="jump", variable=cb7, onvalue=1, offvalue=0, command=multiJump)
c.grid(column=0, row=2)

c = Checkbutton(tab2, text="pot", variable=cb6, onvalue=1, offvalue=0, command=pot)
c.grid(column=2, row=5)

c = Checkbutton(tab2, text="mute", variable=cb8, onvalue=1, offvalue=0, command=muteMic)
c.grid(column=2, row=2)

c = Checkbutton(tab2, text="box", variable=cb12, onvalue=1, offvalue=0, command=Hitbox)
c.grid(column=2, row=3)

c = Checkbutton(tab2, text="spin'n", variable=cb18, onvalue=1, offvalue=0, command=riptideAnywhere)
c.grid(column=0, row=4)

c = Checkbutton(tab2, text="blind", variable=cb26, onvalue=1, offvalue=0, command=blind)
c.grid(column=2, row=4)

c = Checkbutton(tab3, text="test con", variable=cb27, onvalue=1, offvalue=0, command=test)
c.grid(column=0, row=0)

c = Checkbutton(tab2, text="chest esp", variable=cb28, onvalue=1, offvalue=0, command=chest_esp)
c.grid(column=2, row=6)



#===== Section: Tab 2 End =====

#===== Section: Tab 3 =====

cg = IntVar()
cg2 = IntVar()
cg3 = IntVar()
cg4 = IntVar()
cg5 = IntVar()
cg6 = IntVar()
cg7 = IntVar()
cg8 = IntVar()
cg9 = IntVar()
cg10 = IntVar()



window.mainloop()








































#hey ;)