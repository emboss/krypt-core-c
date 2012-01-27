require 'krypt-core'
require_relative 'resources'
require 'stringio'
require 'pp'
require 'openssl'

asn1 = Krypt::ASN1::Sequence.new([])
pp asn1.to_der
#it { should == "\xCE\x01\xFF" }

