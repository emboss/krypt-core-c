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

C = Class.new do
  include Krypt::ASN1::Template::Sequence
  asn1_boolean :a
end

A = Class.new do
  include Krypt::ASN1::Template::Choice 
  asn1_template B, tag: 0, tagging: :IMPLICIT
  asn1_template C, tag: 1, tagging: :EXPLICIT
end

der = "\xA1\x05\x30\x03\x01\x01\xFF"
asn1 = A.parse_der der
p asn1.value
p asn1.value.a

