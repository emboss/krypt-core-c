=begin

= Info

krypt-core API - C version

Copyright (C) 2011
Hiroshi Nakamura <nahi@ruby-lang.org>
Martin Bosslet <martin.bosslet@googlemail.com>
All rights reserved.

= License
This program is distributed under the same license as Ruby.
See the file 'LICENSE' for further details.

=end

require 'mkmf'

arg = ARGV.shift
if arg == "-g"
  debug = true
end

message "=== krypt-core API - C version ===\n"

if debug && CONFIG['GCC'] == 'yes'
  flags = "-fprofile-arcs -ftest-coverage"
  message "!! set #{flags} for coverage !!"
  $CFLAGS += " #{flags}"
  $DLDFLAGS += " #{flags}"
end

message "=== Checking Ruby features ===\n"

have_header("ruby/io.h")
have_func("rb_io_check_byte_readable")


create_header
create_makefile("kryptcore")
message "Done.\n"
