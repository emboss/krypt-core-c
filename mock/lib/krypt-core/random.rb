module Krypt
  module Random
    require 'securerandom'
    SecureRandom = ::SecureRandom
    # Do we have PRNGs independently in krypt?
    Random = ::Random
  end
end
