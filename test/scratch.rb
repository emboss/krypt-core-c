require 'krypt-core'
require_relative 'resources'
require 'stringio'
require 'pp'
require 'openssl'

io = Resources.certificate_io
asn1 = Krypt::Asn1.decode(io)
puts "Asn1 after decode:"
pp asn1
s = asn1.to_der
puts s == Resources.certificate

#require 'benchmark'

#Benchmark.bm do |bm|
#  cert = Resources.certificate
#  n = 100_000

#  bm.report("Krypt::Asn1.decode String") { n.times { Krypt::Asn1.decode(cert) } }
#  bm.report("OpenSSL::Asn1.decode String") { n.times { OpenSSL::ASN1.decode(cert) } }
#  bm.report("Krypt::Asn1.decode File IO") { n.times { Krypt::Asn1.decode(Resources.certificate_io) } }
#  bm.report("Krypt::Asn1.decode String from File IO") { n.times { Krypt::Asn1.decode(Resources.certificate_io.read) } }
#  bm.report("OpenSSL::X509::Certificate String") { n.times { OpenSSL::X509::Certificate.new(Resources.certificate) } }
#end

