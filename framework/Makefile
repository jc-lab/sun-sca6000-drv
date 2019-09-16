#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2006 Sun Microsystems, Inc. All Rights Reserved.
#
#     Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# - Redistribution of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# - Redistribution in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#     Neither the name of Sun Microsystems, Inc. or the names of contributors
# may be used to endorse or promote products derived from this software
# without specific prior written permission.
#     This software is provided "AS IS," without a warranty of any kind. ALL
# EXPRESS OR IMPLIED CONDITIONS, REPRESENTATIONS AND WARRANTIES, INCLUDING
# ANY IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE
# OR NON-INFRINGEMENT, ARE HEREBY EXCLUDED. SUN MICROSYSTEMS, INC. ("SUN")
# AND ITS LICENSORS SHALL NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE
#  AS A RESULT OF USING, MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS
# DERIVATIVES. IN NO EVENT WILL SUN OR ITS LICENSORS BE LIABLE FOR ANY LOST
# REVENUE, PROFIT OR DATA, OR FOR DIRECT, INDIRECT, SPECIAL, CONSEQUENTIAL,
# INCIDENTAL OR PUNITIVE DAMAGES, HOWEVER CAUSED AND REGARDLESS OF THE THEORY
# OF LIABILITY, ARISING OUT OF THE USE OF OR INABILITY TO USE THIS SOFTWARE,
# EVEN IF SUN HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
#     You acknowledge that this software is not designed, licensed or
# intended for use in the design, construction, operation or maintenance of
# any nuclear facility.
#

#ident	"@(#)Makefile.framework	1.2	06/08/21 SMI"

#
# Makefile for the Sun Crypto Framework on the Linux platform
#

#
# Comment out the following line to avoid logging debugging messages
# The DEBUG macros should only be used during development
#
# ccflags-y += -DDEBUG 

ccflags-y += -DLINUX
ccflags-y += -D_KERNEL

#
# Note that Wall ahead of others
#
ccflags-y += -Wall
ccflags-y += -Wno-unknown-pragmas
ccflags-y += -Wno-unused

DRV_NAME	= scaf
KERNEL_VER	?= `uname -r`

BIN_DIR		= $(DESTDIR)/opt/sun/sca6000/bin
DRIVER_DIR	= drv

INCLUDE := /lib/modules/$(KERNEL_VER)/build/
obj-m   := $(DRV_NAME).o
$(DRV_NAME)-objs := sca_io.o sca_spi.o

default $(DRV_NAME).ko:
	$(MAKE) -C ${INCLUDE} SUBDIRS=`pwd` modules
	mkdir -p $(DRIVER_DIR)
	cp $(DRV_NAME).ko $(DRIVER_DIR)/$(DRV_NAME)_$(KERNEL_VER).ko
	cp Module.symvers ../driver/

install: $(DRV_NAME).ko
	install -D -m 644 $(DRV_NAME).ko \
                $(BIN_DIR)/$(DRIVER_DIR)/$(DRV_NAME)_$(KERNEL_VER).ko

clean:
	rm -f *.o *.ko $(DRIVER_DIR)/*.ko .*.ko.cmd *.mod.c .*.o.cmd *~ core
