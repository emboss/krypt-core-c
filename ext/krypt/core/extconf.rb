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

message "=== krypt-core API - C version ===\n"

create_header
create_makefile("kryptcore")
message "Done.\n"


