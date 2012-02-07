require 'rspec'
require 'krypt-core'

describe Krypt::Cipher do
  describe '#new' do
    it "should encrypt" do
      cipher = Krypt::Cipher.new("aes-128-cbc")
      cipher.encrypt
      cipher.key = "\0" * 16
      cipher.iv = "\0" * 16
      (cipher.update('hello,world') + cipher.final).should == "\xD9\x9A\xAA\x40\x8E\x85\x37\x3A\xF9\x11\x90\x31\x1E\x29\xDB\xCD"
    end
  end
end
