require 'krypt-core'
require_relative 'resources'
require 'stringio'
require 'pp'
require 'openssl'

asn1 = Krypt::ASN1.decode(Krypt::ASN1::Set.new(nil).to_der)

pp asn1
pp asn1.value

