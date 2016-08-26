<<<<<<< HEAD
#! /usr/bin/env perl
# Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
=======
#!/usr/local/bin/perl

# mkdir-p.pl
>>>>>>> origin/master

# On some systems, the -p option to mkdir (= also create any missing parent
# directories) is not available.

my $arg;

foreach $arg (@ARGV) {
  $arg =~ tr|\\|/|;
  &do_mkdir_p($arg);
}


sub do_mkdir_p {
  local($dir) = @_;

  $dir =~ s|/*\Z(?!\n)||s;

  if (-d $dir) {
    return;
  }

  if ($dir =~ m|[^/]/|s) {
    local($parent) = $dir;
    $parent =~ s|[^/]*\Z(?!\n)||s;

    do_mkdir_p($parent);
  }

<<<<<<< HEAD
  unless (mkdir($dir, 0777)) {
    if (-d $dir) {
      # We raced against another instance doing the same thing.
      return;
    }
    die "Cannot create directory $dir: $!\n";
  }
=======
  mkdir($dir, 0777) || die "Cannot create directory $dir: $!\n";
>>>>>>> origin/master
  print "created directory `$dir'\n";
}
