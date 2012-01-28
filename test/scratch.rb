require 'krypt-core'
require_relative 'resources'
require 'stringio'
require 'pp'
require 'openssl'

def s(string)
  Krypt::ASN1::OctetString.new(string)
end

def i(int)
  Krypt::ASN1::Integer.new(int)
end

def eoc
  Krypt::ASN1::EndOfContents.new
end

asn1 = i(-1)
pp asn1
pp asn1.to_der

