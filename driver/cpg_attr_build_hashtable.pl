#! /usr/bin/perl -w

#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
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

# ident	"@(#)cpg_attr_build_hashtable.pl	1.7	05/06/30 SMI"

use vars qw($no_modify_warning_string $copyright_string 
	    $explanation_string $pkcs11_symbols_include_string $hashsize);

require "cpg_attr_build_hashtable.pm";

# use strict;

$begin_guard_ident_string = <<BEGIN_GUARD_IDENT
#ifndef _MCA_ATTR_INFOBASE_H
#define	_MCA_ATTR_INFOBASE_H

#pragma ident\t\"\@\(\#\)mca_attr_infobase.h\t0.0\t00\/00\/00 SMI\"
/* The above ident is a fake to keep hdrchk happy */

#ifdef	__cplusplus
extern "C" {
#endif

BEGIN_GUARD_IDENT
;

$end_guard_ident_string = <<'END_GUARD_IDENT'
#ifdef	__cplusplus
}
#endif

#endif /* _MCA_ATTR_INFOBASE_H */
END_GUARD_IDENT
;


$no_modify_warning_string = <<'HDR'
/*
 * This file was machine generated by cpg_attr_build_hashtable.pm
 * @(#)cpg_attr_build_hashtable.pl	1.7	05/06/30 SMI
 *
 * Do not edit this file!
 */
HDR
;

# usage: perl -w cpg_attr_build_hashtable.pl pkcs11t.h > info_file.h

# Note: This was originally written for a more ambitious system than
# is presently used in the mca driver.  It has support for a hierarchy
# of keys/objects, with simple inheritance, as in
# all_objects=>storage_objects=>keys=>private_keys=>RSA_keys.  It also
# has support for various operations/situations.  For example: the unw
# keyword indicates the attributes required to be supplied to an
# unwrap operation, listed below.

# ### type of usage:
# pure in lists to modify objects (set_attribute, copy)
# cr   in createobj
# gen  in generate calls
# unw  in unwrap calls
# act  active objects

# ### values
# 1 required
# 0 optional
# -1 prohibited

# ### attribute info
# ty: type: U CK_ULONG,  A array, B boolean
# def: default behavior: 0: 0 or false or empty, 1: 1 or true
# pri: priority in hash table
# crit: critical security parameter: 0 or missing: false, 1: true

use vars qw($no_modify_warning_string $copyright_string 
	    $explanation_string $pkcs11_symbols_include_string);

my %allpkcs11 = (
 CPGA_CLASS=>{pri=>0, cr=>1, pure=>0, gen=>0, unw=>0, act=>1, ty=>"U"},
 CPGA_TOKEN=>{pri=>1, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>0},
 CPGA_PRIVATE=>{pri=>0, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B"},
 CPGA_LABEL=>{pri=>1, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"A", def=>0},
 CPGA_APPLICATION=>{pri=>2, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"A", def=>0},
# CPGA_VALUE is not critical in a DSA public key.  But fortunately,
# the public key should never be declared sensitive, so we are okay.
# If this becomes a problem, we will need a special case to remove the
# CPG_ATTR_SENSITIVE flag.
 CPGA_VALUE=>{pri=>0, cr=>0, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"A", crit=>1},
 CPGA_OBJECT_ID=>{pri=>2, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"A", def=>0},
 CPGA_CERTIFICATE_TYPE=>{pri=>3, cr=>0, pure=>0, gen=>0, unw=>-1, act=>0, ty=>"U"},
 CPGA_ISSUER=>{pri=>2, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"A", def=>0},
 CPGA_SERIAL_NUMBER=>{pri=>3, cr=>0, pure=>0, gen=>0, unw=>-1, act=>0, ty=>"A", def=>0},
 CPGA_AC_ISSUER=>{pri=>2, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"A", def=>0},
 CPGA_OWNER=>{pri=>2, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"A"},
 CPGA_ATTR_TYPES=>{pri=>2, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"A", def=>0},
 CPGA_TRUSTED=>{pri=>2, cr=>-1, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"B", def=>0},
 CPGA_KEY_TYPE=>{pri=>0, cr=>0, pure=>0, gen=>0, unw=>1, act=>0, ty=>"U"},
 CPGA_SUBJECT=>{pri=>2, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"A", def=>0},
 CPGA_ID=>{pri=>2, cr=>0, pure=>0, gen=>0, act=>0, unw=>0, ty=>"A", def=>0},
 CPGA_SENSITIVE=>{pri=>0, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B"},
 CPGA_ENCRYPT=>{pri=>3, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1},
 CPGA_DECRYPT=>{pri=>3, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1},
 CPGA_WRAP=>{pri=>3, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1},
 CPGA_UNWRAP=>{pri=>3, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1},
 CPGA_SIGN=>{pri=>3, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1},
 CPGA_SIGN_RECOVER=>{pri=>3, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1},
 CPGA_VERIFY=>{pri=>3, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1},
 CPGA_VERIFY_RECOVER=>{pri=>3, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1},
 CPGA_DERIVE=>{pri=>2, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>0},
 CPGA_START_DATE=>{pri=>3, cr=>0, pure=>0, gen=>0, act=>0, unw=>0, ty=>"A", def=>0},
 CPGA_END_DATE=>{pri=>3, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"A", def=>0},
 CPGA_MODULUS=>{pri=>1, cr=>0, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"A"},
 CPGA_MODULUS_BITS=>{pri=>1, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"U"},
 CPGA_PUBLIC_EXPONENT=>{pri=>1, cr=>0, pure=>0, gen=>0, unw=>-1, act=>0, ty=>"A"},
 CPGA_PRIVATE_EXPONENT=>{pri=>1, cr=>0, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"A", crit=>1},
 CPGA_PRIME_1=>{pri=>1, cr=>0, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"A", crit=>1},
 CPGA_PRIME_2=>{pri=>1, cr=>0, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"A", crit=>1},
 CPGA_EXPONENT_1=>{pri=>1, cr=>0, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"A", crit=>1},
 CPGA_EXPONENT_2=>{pri=>1, cr=>0, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"A", crit=>1},
 CPGA_COEFFICIENT=>{pri=>1, cr=>0, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"A", crit=>1},
 CPGA_PRIME=>{pri=>1, cr=>0, pure=>0, gen=>0, act=>0, unw=>-1, ty=>"A"},
 CPGA_SUBPRIME=>{pri=>1, cr=>0, pure=>0, gen=>0, unw=>-1, act=>0, ty=>"A"},
 CPGA_BASE=>{pri=>1, cr=>0, pure=>0, gen=>0, unw=>-1, act=>0, ty=>"A"},
 CPGA_PRIME_BITS=>{pri=>1, cr=>0, pure=>0, gen=>0, unw=>-1, act=>0, ty=>"U"},
 CPGA_SUB_PRIME_BITS=>{pri=>1, cr=>0, pure=>0, gen=>0, unw=>-1, act=>0, ty=>"U"},
 CPGA_VALUE_BITS=>{pri=>1, cr=>0, pure=>0, gen=>0, unw=>-1, act=>0, ty=>"U"},
 CPGA_VALUE_LEN=>{pri=>1, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"U"},
 CPGA_EXTRACTABLE=>{pri=>1, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1},
 CPGA_LOCAL=>{pri=>3, cr=>-1, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"B", def=>0},
 CPGA_NEVER_EXTRACTABLE=>{pri=>3, cr=>-1, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"B", def=>0},
 CPGA_ALWAYS_SENSITIVE=>{pri=>3, cr=>-1, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"B", def=>0},
 CPGA_KEY_GEN_MECHANISM=>{pri=>2, cr=>0, pure=>0, gen=>-1, unw=>0, act=>0, ty=>"U"},
 CPGA_MODIFIABLE=>{pri=>1, cr=>0, pure=>0, gen=>0, act=>0, unw=>0, ty=>"B", def=>1},
 #CPGA_ECDSA_PARAMS=>{pri=>2, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"A"},
 CPGA_EC_PARAMS=>{pri=>2, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"A"},
 CPGA_EC_POINT=>{pri=>2, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"A"},
 CPGA_SECONDARY_AUTH=>{pri=>3, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>0},
 CPGA_AUTH_PIN_FLAGS=>{pri=>3, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>0},
 CPGA_HW_FEATURE_TYPE=>{pri=>3, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"U"},
 CPGA_RESET_ON_INIT=>{pri=>3, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>0},
 CPGA_HAS_RESET=>{pri=>3, cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>0},
);
		 
# The remaining code is for an inheritance-based system currently
# under development.  It will provide data for each individual kind of
# object.  For example, there will be a policy for creating RSA keys
# that will know that they require a modulus, a public exponent, and a
# private exponent, and that value is not allowed.  Furthermore it
# will be feature inheritance.  The top level is allobjects.
# storageobjects inherits all objects, keyobjects inherits storage
# objects, secretkeyobjects inherits keyobjects, and
# DES3secretkeyobjects inherits secretkeyobjects.  But, it is not yet
# done.

my %allobjects = (CPGA_CLASS=>{cr=>1, pure=>0, gen=>1, act=>1});

my %storageobjects = infoMerge(%allobjects, 
 (CPGA_TOKEN=>{cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>0, pri=>0},
 CPGA_PRIVATE=>{cr=>0, pure=>0, gen=>0, unw=>0, act=>1, ty=>"B", pri=>0},
 CPGA_MODIFIABLE=>{cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1, pri=>1},
 CPGA_LABEL=>{cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"A", def=>0, pri=>1}));

my %certobjects = infoMerge(%storageobjects,(
 CPGA_CERTIFICATE_TYPE=>{cr=>1, pure=>0, gen=>-1, unw=>-1, act=>1, ty=>"U", pri=>3},
 CPGA_TRUSTED=>{cr=>-1, pure=>0, gen=>-1, unw=>-1, act=>0, pri=>3}));

my %X509certobjects = infoMerge(%certobjects,
 (CPGA_SUBJECT=>{cr=>1, pure=>0, gen=>-1, unw=>-1, act=>1, ty=>"A", def=>0, pri=>2},
 CPGA_ID=>{cr=>0, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"A", def=>0, pri=>2},
 CPGA_ISSUER=>{cr=>0, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"A", def=>0, pri=>2},
 CPGA_SERIAL_NUMBER=>{cr=>0, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"A", def=>0, pri=>3},
CPGA_VALUE=>{cr=>1, pure=>0, gen=>-1, unw=>-1, act=>1, ty=>"A", pri=>0}));

my %keyobjects = infoMerge(%storageobjects, 
 (CPGA_KEY_TYPE=>{cr=>1, pure=>0, gen=>1, unw=>1, act=>1, ty=>"U", pri=>0},
 CPGA_ID=>{cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"A", def=>1, pri=>2},
 CPGA_START_DATE=>{cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"A", def=>0, pri=>3},
 CPGA_END_DATE=>{cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"A", def=>0, pri=>3},
 CPGA_LOCAL=>{cr=>-1, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"B", pri=>3},
 CPGA_KEY_GEN_MECHANISM=>{cr=>-1, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"U", pri=>2}));
			   
my %secretkeyobjects = infoMerge(%keyobjects,
 (CPGA_SENSITIVE=>{cr=>0, pure=>0, gen=>0, unw=>0, act=>1, ty=>"B", pri=>0},
 CPGA_ENCRYPT=>{cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1, pri=>3},
 CPGA_DECRYPT=>{cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1, pri=>3},
 CPGA_SIGN=>{cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1, pri=>3},
 CPGA_VERIFY=>{cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1, pri=>3},
 CPGA_WRAP=>{cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1, pri=>3},
 CPGA_UNWRAP=>{cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1, pri=>3},
 CPGA_EXTRACTABLE=>{cr=>0, pure=>0, gen=>0, unw=>0, act=>0, ty=>"B", def=>1, pri=>1},
 CPGA_ALWAYS_SENSITIVE=>{cr=>-1, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"B", pri=>3},
 CPGA_NEVER_EXTRACTABLE=>{cr=>-1, pure=>0, gen=>-1, unw=>-1, act=>0, ty=>"B", pri=>3}));

my %DES3secretkeyobjects = infoMerge(%secretkeyobjects,
 (CPGA_VALUE=>{cr=>1, pure=>0, gen=>-1, unw=>-1, act=>1, ty=>"A", crit=>1, pri=>0}));

$hashsize = 128;

print "$copyright_string\n";
print "$begin_guard_ident_string\n";
print "$no_modify_warning_string\n";
print "$explanation_string\n";

printf "#define\tCPG_ATTR_POLICY_PKCS11_PURE_INITIALIZER %s\n", formatinitializer(\%allpkcs11, "pure", $hashsize);

printf "#define\tCPG_ATTR_POLICY_PKCS11_ACTIVE_INITIALIZER %s\n", formatinitializer(\%allpkcs11, "act", $hashsize);

printf "#define\tCPG_ATTR_POLICY_PKCS11_CREATE_INITIALIZER %s\n", formatinitializer(\%allpkcs11, "cr", $hashsize);

printf "#define\tCPG_ATTR_POLICY_PKCS11_GEN_INITIALIZER %s\n", formatinitializer(\%allpkcs11, "gen", $hashsize);

printf "#define\tCPG_ATTR_POLICY_PKCS11_UNWRAP_INITIALIZER %s\n", formatinitializer(\%allpkcs11, "unw", $hashsize);

print $end_guard_ident_string;