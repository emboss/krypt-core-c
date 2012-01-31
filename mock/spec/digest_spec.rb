require 'rspec'
require 'krypt-core'

describe Krypt::Digest do
  describe Krypt::Digest::SHA1 do
    subject { Krypt::Digest::SHA1.new }

    describe '#hexdigest' do
      it "should calculate SHA1" do
        subject.hexdigest('hello,world').should == '74f4f4eb1947b9ca08e5e68d04d081808777f9a0'
      end
    end
  end
end
