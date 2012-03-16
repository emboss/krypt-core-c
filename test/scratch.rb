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

A = Class.new do
  include Krypt::ASN1::Template::Sequence 
  asn1_any :a
  asn1_boolean :b
end

der = "\x30\x0B\x30\x06\x02\x01\x01\x02\x01\x01\x01\x01\xFF"
asn1 = A.parse_der der

p asn1.a
p asn1.b

