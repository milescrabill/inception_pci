Inception plus native Pcie
==========================

This fork of inception includes support for native driverless pcie using 
SLOTSCREAMER from the NSA Playset(TM).
This code runs on the USB side of the SLOTSCREAMER device. There is no
software needed on the pcie/expresscard/thunderbolt side.

There are still TODOs in the code but it mostly works. I tested it on
ubuntu 14.04. here's the setup sequence:

```
git clone https://github.com/walac/pyusb.git
cd pyusb
sudo python3 setup.py install
cd ..
git clone  git://git.freddie.witherden.org/forensic1394.gitm
cd forensic1394/
mkdir build
cd build
cmake -G"Unix Makefiles" ../
make
sudo make install
cd ../python
sudo python3 setup.py install
cd ../../
git clone https://github.com/milescrabill/inception_pci.git
cd inception_pci
sudo incept -N
```

notes:
* inception wants python3 so make sure pyusb and forensic1394 are installed there
* forensic1394 is not used but is a dependency of inception

changes:
* added a SLOTSCREMER class to inception/util.py modeled after MemoryFile
* added necessary imports to util.py
* added pciemode to cfg.py and -N NativePCIe option in incept
* added switches for pcimode to both screenlock.py and memdump.py
* tweaked ascii art graphic

todos:
* support byte enables and padding of read/writes. Right now it just rounds up to dword
* put better error checking in everything
* figure out if usb init code could be cleaner
* figure out why libusb error happens on exit
* enhance performace? perhaps setup and use DMA directly on the 3380?
* figure out how to remove pyusb requirement when using firewire
* figure out how to remove forensic1394 requirement when using pcie


Inception
=========

Inception is a FireWire physical memory manipulation and hacking tool 
exploiting IEEE 1394 SBP-2 DMA. The tool can unlock (any password accepted) 
and escalate privileges to Administrator/root on almost* any powered on 
machine you have physical access to. The tool can attack over FireWire, 
Thunderbolt, ExpressCard, PC Card and any other PCI/PCIe interfaces.

Inception aims to provide a stable and easy way of performing intrusive and 
non-intrusive memory hacks in order to unlock live computers using FireWire 
SBP-2 DMA. It it primarily attended to do its magic against computers that 
utilize full disk encryption such as BitLocker, FileVault, TrueCrypt or 
Pointsec. There are plenty of other (and better) ways to hack a machine that 
doesn't pack encryption.

As of version 0.3.5, it is able to unlock the following x86 and x64 operating
systems:

|OS           |Version        |Unlock lock screen|Escalate privileges|Dump memory < 4 GiB|
|:------------|:--------------|:----------------:|:-----------------:|:-----------------:|
|Windows 8    |8.1            |        Yes       |        Yes        |        Yes        |
|Windows 8    |8.0            |        Yes       |        Yes        |        Yes        |
|Windows 7    |SP1            |        Yes       |        Yes        |        Yes        |
|Windows 7    |SP0            |        Yes       |        Yes        |        Yes        |
|Windows Vista|SP2            |        Yes       |        Yes        |        Yes        |
|Windows Vista|SP1            |        Yes       |        Yes        |        Yes        |
|Windows Vista|SP0            |        Yes       |        Yes        |        Yes        |
|Windows XP   |SP3            |        Yes       |        Yes        |        Yes        |
|Windows XP   |SP2            |        Yes       |        Yes        |        Yes        |
|Windows XP   |SP1            |                  |                   |        Yes        |
|Windows XP   |SP0            |                  |                   |        Yes        |
|Mac OS X     |Mavericks      |       Yes (1)    |       Yes (1)     |      Yes (1)      |
|Mac OS X     |Mountain Lion  |       Yes (1)    |       Yes (1)     |      Yes (1)      |
|Mac OS X     |Lion           |       Yes (1)    |       Yes (1)     |      Yes (1)      |
|Mac OS X     |Snow Leopard   |        Yes       |        Yes        |        Yes        |
|Mac OS X     |Leopard        |                  |                   |        Yes        |
|Ubuntu (2)   |Saucy          |        Yes       |        Yes        |        Yes        |
|Ubuntu       |Raring         |        Yes       |        Yes        |        Yes        |
|Ubuntu       |Quantal        |        Yes       |        Yes        |        Yes        |
|Ubuntu       |Precise        |        Yes       |        Yes        |        Yes        |
|Ubuntu       |Oneiric        |        Yes       |        Yes        |        Yes        |
|Ubuntu       |Natty          |        Yes       |        Yes        |        Yes        |
|Ubuntu       |Maverick       |      Yes (3)     |       Yes (3)     |        Yes        |
|Ubuntu       |Lucid          |      Yes (3)     |       Yes (3)     |        Yes        |
|Linux Mint   |13             |        Yes       |        Yes        |        Yes        |
|Linux Mint   |12             |        Yes       |        Yes        |        Yes        |
|Linux Mint   |12             |        Yes       |        Yes        |        Yes        |

(1): If FileVault 2 is enabled, the tool will only work when the operating
     system is unlocked.
(2): Other Linux distributions that use PAM-based authentication may also work 
     using the Ubuntu signatures.
(3): x86 only.

The tool also effectively enables escalation of privileges, for instance via 
the `runas` or `sudo -s` commands, respectively. More signatures will be added.
The tool makes use of the `libforensic1394` library courtesy of Freddie Witherden
under a LGPL license.


Key data
--------

 * Version:	0.3.5
 * License:	GPL
 * Author:	Carsten Maartmann-Moe (carsten@carmaa.com) AKA ntropy
 * Twitter:	@breaknenter
 * Site:	http://www.breaknenter.org/projects/inception
 * Source:	https://github.com/carmaa/inception


Requirements
------------

Inception requires:

 * Attacker machine: Linux or Mac OS X (host / attacker machine) with a FireWire or Thunderbolt interface, or an ExpressCard/PCMCIA expansion port. Linux is currently recommended due to buggy firewire interfaces on OS X
 * Victim machine: A FireWire or Thunderbolt interface, or an ExpressCard/PCMCIA expansion port


Installation
------------

For now you should be able to run the tool without any installation except
dependencies on Mac OS X and Linux distros. Check out the README file in 
`libforensic1394` for installation and FireWire pro-tips.

### Dependencies

 * Python 3
 * git
 * gcc (incl. g++)
 * cmake
 * [libforensic1394] [3]

#### Linux

On Debian-based distributions the installation command lines can be summarized
as:

	sudo apt-get install git cmake python3 g++

#### Mac OS X

On OS X, you can install the tool dependencies with [homebrew] [4]:

	brew install git cmake python3

After installing the dependencies, download and install libforensic1394:

	git clone git://git.freddie.witherden.org/forensic1394.git
	cd forensic1394
	cmake CMakeLists.txt
	sudo make install
	cd python
	sudo python3 setup.py install

### Download and install Inception

	git clone git://github.com/carmaa/inception.git
	cd inception
	sudo python3 setup.py install


Usage
-----

 1. Connect the attacker machine (host) and the victim (target) with a FireWire cable
 2. Run Inception
 3. Logon to the target using any password

Simply type:

	incept

For a more complete and up-to-date description, please run:

	incept -h

or see the [tool home page] [5].


Known bugs / caveats
--------------------

Please see the [tool home page] [5].
   

Troubleshooting
---------------

Please see the [tool home page] [5].


Planned features
----------------

 * Insert and execute memory-only rootkit
 * Other winlockpwn techniques
 
 
Development history
-------------------
 
 * 0.0.1 - First version, supports basic Windows XP SP3, Vista and 7, Mac OS X
           and Ubuntu Gnome unlocking  
 * 0.0.2 - Added signatures for early XP SP3, and Windows 7 x86 and x64 SP1  
 * 0.0.3 - Added some signatures (thanks Tekkenhead) and error handling  
 * 0.0.4 - Added businfo to display connected FireWire devices as well as memory
           dumping capabilities  
 * 0.0.5 - Enhanced memory dumping abilities and added samples catalog  
 * 0.0.6 - Added unit testing  
 * 0.0.7 - Updated Ubuntu signatures and priv. escalation - thanks Adel Khaldi
           from Algeria  
 * 0.0.8 - Fixed Ubuntu unlock and privilege escalation patches - single patch
           for double the action
 * 0.1.0 - First minor version! Added signatures for OS X and Vista, plus quite
           a few bug fixes
 * 0.1.1 - Added signatures for Ubuntu 12.04 LTS
 * 0.1.2 - Patched several bugs
 * 0.1.3 - Patched OS X 10.6.8 x64 signature bug
 * 0.1.4 - Added manual mode easing testing of new signatures
 * 0.2.0 - Added signatures for OS X Mountain Lion (10.8) and Windows 8
 * 0.2.1 - Added signatures for Ubuntu 12.10
 * 0.2.2 - Added signatures for Linux Mint
 * 0.2.3 - General code cleanup, and nicer and more consistent output
 * 0.2.4 - Added a progress bar 
 * 0.2.5 - No longer needed to be root to run the tool
 * 0.2.6 - Bug fixes
 * 0.3.0 - Added support for Ubuntu 13.04 targets
 * 0.3.1 - Added support for OS X Maverics and Windows 8.1
 * 0.3.2 - Bug fixes and support for Ubuntu 13.10
 * 0.3.3 - Bug fixes regarding output and error handling
 * 0.3.4 - Maestro!
 * 0.3.5 - Added signatures for Ubuntu 10.04 and 10.10 x86
 
 
Disclaimer
----------
Do no evil with this tool. Also, I am a pentester, not a developer. So if you
see weird code that bugs your pythonesque purity senses, drop me a note on how
I can improve it. Or even better, fork my code, change it and issue a pull
request.


[3]: http://freddie.witherden.org/tools/libforensic1394/
[4]: http://mxcl.github.io/homebrew/
[5]: http://www.breaknenter.org/projects/inception/
