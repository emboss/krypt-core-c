require 'rake'
require 'rake/extensiontask'

spec = Gem::Specification.new do |s|
  s.name = 'krypt-core'
  s.version = '0.0.1'
  s.author = 'Hiroshi Nakamura, Martin Bosslet'
  s.email = 'Martin.Bosslet@googlemail.com'
  s.homepage = 'https://github.com/emboss/krypt-core'
  s.extensions << 'ext/krypt/core/extconf.rb'
  s.files = %w(LICENSE README Rakefile) + Dir.glob("{bin,ext,lib,spec,test}/**/*")
  s.test_files = FileList['test/**/test_*.rb']
  s.require_path = "lib"
end

Rake::ExtensionTask.new do |ext|
  ext.name = "kryptcore"
  ext.ext_dir = "ext/krypt/core"
  ext.lib_dir = "lib"
end


