require 'krypt-core'
require_relative 'resources'
require 'stringio'
require 'pp'
require 'openssl'

rsaoid = "1.2.840.113549.1.1.1"
oid = OpenSSL::ASN1::ObjectId.new("rsaEncryption")
der = oid.to_der
puts oid.oid
val = Krypt::Asn1.decode(der)
pp val
pp val.value
puts val.value == oid.oid

noid = Krypt::Asn1::ObjectId.new(rsaoid)
puts noid.to_der == der


