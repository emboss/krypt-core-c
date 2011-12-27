require 'krypt-core'
require_relative 'resources'
require 'stringio'

def parse_once(io)
  parser = Krypt::Asn1::Parser.new
  while header = parser.next(io) do 
    puts "Tag: #{header.tag}"
    puts "Tag class: #{header.tag_class}"
    puts "Header Length: #{header.header_length}"
    puts "Length: #{header.length}"
    unless header.constructed?
      header.skip_value
    end
  end
end

def parse_once_value(io)
  parser = Krypt::Asn1::Parser.new
  while header = parser.next(io) do 
    puts header
    unless header.constructed?
      p header.value
    end
  end
end

parse_once(Resources.certificate_io)
parse_once(StringIO.new(Resources.certificate))
parse_once_value(Resources.certificate_io)
parse_once_value(StringIO.new(Resources.certificate))

