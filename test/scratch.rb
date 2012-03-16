# encoding: UTF-8

require 'krypt'
require_relative 'resources'
require 'stringio'
require 'pp'
require 'openssl'
require 'base64'
require 'benchmark'

def s(string)
  Krypt::ASN1::OctetString.new(string)
end

def i(int)
  Krypt::ASN1::Integer.new(int)
end

def eoc
  Krypt::ASN1::EndOfContents.new
end

puts "-PAUSE: Attach debugger-"
gets

B = Class.new do
  include Krypt::ASN1::Template::Sequence 
  asn1_integer :a
end

A = Class.new do
  include Krypt::ASN1::Template::Sequence 
  asn1_sequence_of :a, B
end

der = "\x30\x0C\x30\x0A\x30\x03\x02\x01\x01\x30\x03\x02\x01\x01"
asn1 = A.parse_der der

p asn1.a

