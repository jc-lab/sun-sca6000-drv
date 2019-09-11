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

#pragma ident	"@(#)cpg_attr_build_hashtable.pm	1.4	05/09/08 SMI"

# use strict;

use vars qw(@timelist $year);

@timelist = localtime(time);
$year = $timelist[5] + 1900;

$copyright_string = <<HDR
/*
 * Copyright $year Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
HDR
;


$explanation_string = <<'EXPL'
/*
 * Each non-null item has the form:
 * {attr, / * d=delta b=original_bucket p=priority * /
 *          attributes...
 * }
 *
 * Each null item has the form: {~0U, ~0U}.
 */
EXPL
;


my $gr = (sqrt(5) - 1)/2;
my $grscaled = int(2**31 * (sqrt(5) -1));

my $headers_printed = 0;


 
my %pk11data = ();

open PK11ATTR, $ARGV[0] or die $!;
while (<PK11ATTR>) {
  m/\#define\s+(CPGA_\w+)\s+(0x[\da-fA-F]+)/ or next;
# The eval converts hex to a number, I think.
  $pk11data{$1} = eval $2;
}
close PK11ATTR;


sub hash ( $$ ) {
  my ($k, $size) = @_;
  my $v1 = $gr * $k;
  $v1 -= int($v1);
  return int($v1 * $size);
}


sub findemptyslot ( $$$ ) {
  my ($k, $hasharrayref, $size) = @_;
  my $h = hash($k, $size);
  my $horig = $h;
  while (defined $hasharrayref->[$h]) {
    $h = ($h + 1) % $size;
    $h == $horig and die "table full";
  }
  return $h;
}

 
sub initToDefineRHS ( $ ) {
  my $s = $_[0];
  my $out = "\n$s";
  $out =~ s/\n/\\\n/g;
  # strip off last backslash
  $out =~ s/\\\n$/\n/;
  return $out;
}
  
sub infoMerge ( @ ) {
  return @_
}
  
sub formatinitializer ( $$$ ) {
  my ($inhashref, $mode, $secondary_table_size) = @_;
  my %workhash = ();
  my @outhash = (undef) x $secondary_table_size;
  my $lg2_secondary_table_size = int(log($secondary_table_size)/log(2) +.5);

# At the present time we cheat as follows:
# 1.  We don't list signed vs unsigned, 
#     since in PKCS#11 everything is unsigned.
# 2.  We don't list element size for arrays, since in PKCS#11 all arrays
#     are byte arrays.


# Augment the input table, by adding a sym field and the entire output
# string, then build the out hash (array)

  my $insym;
  foreach $insym (keys %$inhashref) {
    next if ($inhashref->{$insym}->{$mode} == -1);
    $workhash{$insym}->{sym}=$insym;
    $workhash{$insym}->{pri}=$inhashref->{$insym}->{pri};
    my $valstring = "CPG_ATTR_ISUNSIGNED";
    $inhashref->{$insym}->{crit} and $valstring .= " |\nCPG_ATTR_SENSITIVE";
    if ($inhashref->{$insym}->{ty} eq "U") {
      $valstring .= " |\nCPG_ATTR_DATASIZE32";
    }
    if ($inhashref->{$insym}->{ty} eq "B") {
      $valstring .= " |\nCPG_ATTR_DATASIZE8";
    }
    if ($inhashref->{$insym}->{ty} eq "A") {
      $valstring .= " |\nCPG_ATTR_DATASIZE8 |\nCPG_ATTR_ISARRAY";
    }
    if ($inhashref->{$insym}->{$mode} == 1) {
      $valstring .= " |\nCPG_ATTR_REQUIRED";
    }
    if (defined $inhashref->{$insym}->{def}) {
      $valstring .= sprintf " |\nCPG_ATTR_DEFAULT_%d", 
          $inhashref->{$insym}->{def};
    };
    $workhash{$insym}->{val}=$valstring;
  }

  my $eref;
  
  for $eref (sort {$a->{pri} <=> $b->{pri}} values %workhash) {
    my $numerickey = $pk11data{$eref->{sym}};
    defined $numerickey or die sprintf "undefined symbol %s", $eref->{sym};
    my $k = findemptyslot($numerickey, \@outhash, $secondary_table_size);
    $eref->{bucket} =  hash($numerickey, $secondary_table_size);
    $eref->{delta} = $k - $eref->{bucket};
    $outhash[$k] = $eref;
  }
  # convert to text
  my $outtext = "\{\n";
  my $c = 0;
  scalar(@outhash) == $secondary_table_size or 
    die "outhhash size not $secondary_table_size";
  for $eref (@outhash) {
    if ($eref) {
      my $val = $eref->{val};
      $val =~ s/^/\t\t\t/mg; # indent everything
      $outtext .= sprintf("\t\{\n\t\t%s,  /* d=%d b=%d p=%d */\n%s\n\t\}", 
			  $eref->{sym}, $eref->{delta}, $eref->{bucket},
			  $eref->{pri}, $val);
    } else {
      $outtext .= "\t\{~0U, ~0U\}";
    }
    $outtext .= $c++ == $#outhash ? "\n" : ",\n";
  }

  $outtext .= "\}";

  return initToDefineRHS($outtext);
}



