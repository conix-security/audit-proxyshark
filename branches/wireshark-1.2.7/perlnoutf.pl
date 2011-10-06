#!/usr/bin/perl -w

# $Id: perlnoutf.pl 12334 2004-10-17 23:03:11Z guy $

# Call another Perl script, passing our caller's arguments, with
# environment variables unset so perl doesn't interpret bytes as UTF-8
# characters.

use strict;

delete $ENV{LANG};
delete $ENV{LANGUAGE};
delete $ENV{LC_ALL};
delete $ENV{LC_CTYPE};

system("$^X -w @ARGV");
