require 'krypt-core'
require_relative 'resources'
require 'stringio'

io = Resources.certificate_io
parser = Krypt::Asn1::Parser.new

header = parser.next(io)
puts header.tag
puts header.tag_class
puts header.header_length
puts header.length
puts

#io = StringIO.new(Resources.certificate)
#parser = Krypt::Asn1::Parser.new
#header = parser.next(io)
#puts header.tag
#puts header.tag_class
#puts header.header_length
#puts header.length



