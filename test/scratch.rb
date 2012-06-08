# encoding: UTF-8

require 'krypt'
require_relative 'resources'
require 'stringio'
require 'pp'
require 'openssl'
require 'base64'
require 'benchmark'

data = "test"
enc = Krypt::Hex.encode(data)
puts enc
puts Krypt::Hex.decode(enc)

io = StringIO.new
hex = Krypt::Hex::Encoder.new(io)
hex << "t"
hex << "e"
hex << "s"
hex << "t"
hex.close

result = io.string
puts result
puts result == enc

io = StringIO.new("74657374")
hex = Krypt::Hex::Decoder.new(io)
res = ""
res << hex.read(1)
res << hex.read(1)
res << hex.read(1)
res << hex.read(1)

puts res
p hex.read(1)
hex.close
