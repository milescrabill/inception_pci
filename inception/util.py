'''
Inception - a FireWire physical memory manipulation and hacking tool exploiting
IEEE 1394 SBP-2 DMA.

Copyright (C) 2011-2013  Carsten Maartmann-Moe

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Created on Jun 19, 2011

@author: Carsten Maartmann-Moe <carsten@carmaa.com> aka ntropy
'''
from inception import cfg, term
from subprocess import call
import binascii
import os
import platform
import sys
import usb.core
import usb.util
import struct
import math


def hexstr2bytes(s):
    '''
    Takes a string of hexadecimal characters preceded by '0x' and returns the
    corresponding byte string. That is, '0x41' becomes b'A'
    '''
    if isinstance(s, str) and s.startswith('0x'):
        s = s.replace('0x', '') # Remove '0x' strings from hex string
        if len(s) % 2 == 1: s = '0' + s # Pad with zero if odd-length string
        return binascii.unhexlify(bytes(s, sys.getdefaultencoding()))
    else:
        raise BytesWarning('Not a string starting with \'0x\': {0}'.format(s))
    

def bytes2hexstr(b):
    '''
    Takes a string of bytes and returns a string with the corresponding
    hexadecimal representation. Example: b'A' becomes '0x41'
    '''
    if isinstance(b, bytes):
        return '0x' + bytes.decode(binascii.hexlify(b))
    else:
        raise BytesWarning('Not a byte string')
        

def bytelen(s):
    '''
    Returns the byte length of an integer
    '''
    return (len(hex(s))) // 2


def int2binhex(i):
    '''
    Converts positive integer to its binary hexadecimal representation
    '''
    if i < 0:
        raise TypeError('Not a positive integer: {0}'.format(i))
    return hexstr2bytes(hex(i))


def open_file(filename, mode):
    '''
    Opens a file that are a part of the package. The file must be in the folder
    tree beneath the main package
    '''
    this_dir, this_filename = os.path.split(__file__) #@UnusedVariable
    path = os.path.join(this_dir, filename)
    return open(path, mode)
    

def parse_unit(size):
    '''
    Parses input in the form of a number and a (optional) unit and returns the
    size in either multiplies of the page size (if no unit is given) or the
    size in KiB, MiB or GiB
    '''
    size = size.lower()
    if size.find('kib') != -1 or size.find('kb') != -1:
        size = int(size.rstrip(' kib')) * cfg.KiB
    elif size.find('mib') != -1 or size.find('mb') != -1:
        size = int(size.rstrip(' mib')) * cfg.MiB
    elif size.find('gib') != -1 or size.find('gb') != -1:
        size = int(size.rstrip(' gib')) * cfg.GiB
    else:
        size = int(size) * cfg.PAGESIZE
    return size


def detectos():
    '''
    Detects host operating system
    '''
    return platform.system()


def unload_fw_ip():
    '''
    Unloads IP over FireWire modules if present on OS X
    '''
    term.poll('IOFireWireIP on OS X may cause kernel panics. Unload? [Y/n]: ')
    unload = input().lower()
    if unload in ['y', '']:
        status = call('kextunload /System/Library/Extensions/IOFireWireIP.kext',
                      shell=True)
        if status == 0:
            term.info('IOFireWireIP.kext unloaded')
            term.info('To reload: sudo kextload /System/Library/Extensions/' +
                 'IOFireWireIP.kext')
        else:
            term.fail('Could not unload IOFireWireIP.kext')

def cleanup():
    '''
    Cleans up at exit
    '''
    for egg in cfg.eggs:
        egg.terminate()


def restart():
    '''
    Restarts the current program. Note: this function does not return. 
    '''
    python = sys.executable
    os.execl(python, python, * sys.argv)

class SlotScreamer:
    '''
    interface to the SlotScreamer native PCIe device over USB with pyusb
    '''

    def __init__(self):
        '''
        Constructor
        '''
        # find our device
        dev = usb.core.find(idVendor=0x0525, idProduct=0x3380)
        assert dev is not None, 'device not found'
        dev.set_configuration()
        cfg = dev.get_active_configuration()
        intf = cfg[0,0]

        self.pciin = usb.util.find_descriptor(intf,custom_match = lambda e: e.bEndpointAddress==0x8e)
        assert self.pciin is not None, 'pciin endpoint not found'
        term.info('PCIIN found: '+str(self.pciin)+'\n')
        
        self.pciout = usb.util.find_descriptor(intf,custom_match = lambda e: e.bEndpointAddress==0xe)
        assert self.pciout is not None, 'pciout endpoint not found'
        term.info('PCIOUT found: '+str(self.pciout)+'\n')
        self.cache=[]
    
    def read(self, addr, numb, buf=None):
        try:
            # round down to multiple of 256
            offset = addr % 256
            baseAddress = addr - offset
            endOffset = (addr+numb) % 256
            endAddress = addr + numb - offset+256
            # cache most recent read
            # check if anything is cached
            if (len(self.cache)>0):
                if((self.cacheBase<=addr)and((self.cacheBase+len(self.cache))>(addr+numb))):
                    return bytes(self.cache[(addr-self.cacheBase):(addr+numb)-self.cacheBase])
            self.cache=[]
            self.cacheBase=baseAddress
            while baseAddress<endAddress:
                self.pciout.write(struct.pack('BBBBI',0xcf,0,0,0x40,baseAddress))
                self.cache+=self.pciin.read(0x100)
                baseAddress+=256
        except IOError:
            self.cache=[]
        return bytes(self.cache[offset:offset+numb])
		  
    def readv(self,req):
        # sort requests so sequential reads are cached
        #req.sort()
        for r in req:
            yield(r[0], self.read(r[0],r[1]))

    def write(self, addr, buf):
        #calculate buffer
        offset=addr%256
        baseAddress=addr-numb
        byteCount=len(buf)
        endOffset=(addr+numb)%256
        endAddress=addr+numb-endOffset+256
        #read to fill buffer
        readbuf=self.readPCI(baseAddress,endAddress-baseAddress)
        #modify buffer
        for i in range(offset,endOffset):
            readbuf[i]=buf[i-offset]
        #write buffer
        bufferIndex=0
        while baseAddress<endAddress:
            subbuf=readbuf[bufferIndex:bufferIndex+128]
            self.pciout.write(struct.pack('BBBBI'+'B'*256,0x4f,0,0,0x20,baseAddress,*subbuf))
            baseAddress+=128
            bufferIndex+=128
        self.cache=[]
        
    def close(self):
        self.cache=[]

class MemoryFile:
    '''
    File that exposes a similar interface as the FireWire class. Used for
    reading from RAM memory files of memory dumps
    '''

    def __init__(self, file_name, pagesize):
        '''
        Constructor
        '''
        self.file = open(file_name, mode='r+b')
        self.pagesize = pagesize
    
    def read(self, addr, numb, buf=None):
        self.file.seek(addr)
        return self.file.read(numb)  
    
    def readv(self, req):
        for r in req:
            self.file.seek(r[0])
            yield (r[0], self.file.read(r[1]))
    
    def write(self, addr, buf):
        if cfg.forcewrite:
            term.poll('Are you sure you want to write to file [y/N]? ')
            answer = input().lower()
            if answer in ['y', 'yes']:
                self.file.seek(addr)
                self.file.write(buf)
        else:
            term.warn('File not patched. To enable file writing, use the ' +
                      '--force-write switch')
    
    def close(self):
        self.file.close()
    
    

