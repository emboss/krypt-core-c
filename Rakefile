require 'rake'
require 'rake/extensiontask'
require 'rspec/core/rake_task'

KRYPT_HOME = '../krypt'

$config_options = []

task :default => :compile

task :clean do
  rm_f FileList['*.gcov']
  rm_f 'kryptcore.info'
  rm_rf 'coverage'
end

Rake::ExtensionTask.new('kryptcore') do |ext|
  ext.ext_dir = "ext/krypt/core"
  ext.lib_dir = "lib"
  ext.config_options = $config_options
end

RSpec::Core::RakeTask.new(:spec) do |spec|
  spec.pattern = File.join(KRYPT_HOME, 'spec/**/*_spec.rb')
end

task 'enable-coverage' do
  # ugly, but we cannot define 2 ExtensionTasks for the same ext.name.
  $config_options << '-g'
end

desc 'requires gcov and lcov in $PATH'
task 'report-coverage' do
  outdir = File.dirname(Dir['tmp/**/Makefile'].first)
  sh "gcov -o #{outdir} ext/krypt/core/krypt*.h ext/krypt/core/krypt*.c"
  sh "lcov -c -d . --output-file kryptcore.info"
  sh "lcov -r kryptcore.info ruby.h --output-file kryptcore.info"
  sh "lcov -r kryptcore.info '*include*' --output-file kryptcore.info"
  rm_f FileList['*.gcov']
  sh "genhtml -o coverage kryptcore.info"
end

desc 'Build ext for coverage and generate a coverage report of spec.'
task 'coverage' => ['enable-coverage', 'compile', 'spec', 'report-coverage']

task :build => :compile
