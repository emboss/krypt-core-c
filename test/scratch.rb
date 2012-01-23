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

time = Time.new
puts time

asn1 = Krypt::Asn1::GeneralizedTime.new(time)
der = asn1.to_der
asn2 = Krypt::Asn1.decode(der)
pp asn2

time2 = asn2.value
puts time2
puts time2.to_i == time.to_i

puts der == asn2.to_der
ossl = OpenSSL::ASN1::GeneralizedTime.new(time).to_der
puts ossl == asn2.to_der

pp ossl
pp asn2.to_der

