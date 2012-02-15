# encoding: UTF-8

require 'krypt-core'
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

