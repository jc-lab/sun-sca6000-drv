#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2007 Sun Microsystems, Inc. All Rights Reserved.
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

#ident	"@(#)Makefile.driver	1.2	07/08/03 SMI"

#
# Makefile for Mars device driver on the Linux platform
#

PERL=/usr/bin/perl

#
# Comment out the following line to avoid logging debugging messages
# The DEBUG macros should only be used during development
#
# CFLAGS += -DDEBUG

CFLAGS += -DLINUX
CFLAGS += -D_KERNEL

#
# Note that Wall has to be ahead of other warnings
#
CFLAGS += -Wall
CFLAGS += -Wno-unknown-pragmas
CFLAGS += -Wno-unused
CFLAGS += -Wno-missing-braces
CFLAGS += -std=gnu99

DRV_NAME	= mca
MCACTL_NAME	= mcactl
KERNEL_VER	?= `uname -r`
BIN_DIR		= $(DESTDIR)/opt/sun/sca6000/bin
DRV_DIR		= drv

# Use this to add additional include dirs to kernel module builds
CPPFLAGS +=	-I$(TOP)/driver

INCLUDE := /lib/modules/$(KERNEL_VER)/build/
obj-m   := $(DRV_NAME).o $(MCACTL_NAME).o

$(DRV_NAME)-objs := mca_main.o mca_debug.o mca_kstat.o mca_kcf.o mca_aes.o \
	mca_wrap.o mca_table.o mca_rng.o mca_login.o mca_keygen.o \
	mca_hw.o mca_log.o mca_swrsa.o \
	mca_upcall.o mca_keystore.o mca_hash.o mca_hmac.o \
	mca_rsa.o mca_dsa.o mca_ecdsa.o mca_3des.o cpg_attr.o mca_derive.o

$(MCACTL_NAME)-objs := mcactl_main.o

default $(DRV_NAME).ko: mca_attr_infobase.h
	make -C ${INCLUDE} SUBDIRS=`pwd` modules
	mkdir -p $(DRV_DIR)
	cp $(DRV_NAME).ko $(DRV_DIR)/$(DRV_NAME)_$(KERNEL_VER).ko
	cp $(MCACTL_NAME).ko $(DRV_DIR)/$(MCACTL_NAME)_$(KERNEL_VER).ko

install: $(DRV_NAME).ko $(MCACTL_NAME).ko
	install -D -m 644 $(DRV_NAME).ko \
		$(BIN_DIR)/$(DRV_DIR)/$(DRV_NAME)_$(KERNEL_VER).ko
	install -D -m 644 $(MCACTL_NAME).ko \
		$(BIN_DIR)/$(DRV_DIR)/$(MCACTL_NAME)_$(KERNEL_VER).ko

mca_attr_infobase.h: cpg_attr_build_hashtable.pl cpg_attr_build_hashtable.pm
	$(PERL) -w cpg_attr_build_hashtable.pl mca_cf.h > mca_attr_infobase.h

clean:
	rm -f *.o *.ko $(DRV_DIR)/*.ko .*.ko.cmd *.mod.c .*.o.cmd *~ core mca_attr_infobase.h
