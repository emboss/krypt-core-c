require 'rake'
require 'rake/extensiontask'
require 'rubygems/package_task'

task :default => :compile

require 'bundler'
Bundler::GemHelper.install_tasks

Rake::ExtensionTask.new do |ext|
  ext.name = "kryptcore"
  ext.ext_dir = "ext/krypt/core"
  ext.lib_dir = "lib"
end


