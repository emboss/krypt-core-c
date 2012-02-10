require 'rake'
require 'rake/extensiontask'
require 'rspec/core/rake_task'
require 'rdoc/task'
require_relative 'lib/krypt-core/version'

KRYPT_HOME = '../krypt'

$config_options = []

task :default => :compile

task :clean do
  rm_f FileList['*.gcov']
end

Rake::ExtensionTask.new('kryptcore') do |ext|
  ext.ext_dir = "ext/krypt/core"
  ext.lib_dir = "lib"
  ext.config_options = $config_options
end

RSpec::Core::RakeTask.new('spec-run') do |spec|
  spec.pattern = File.join(KRYPT_HOME, 'spec/**/*_spec.rb')
  spec.fail_on_error = false
end

task 'enable-coverage' do
  # ugly, but we cannot define 2 ExtensionTasks for the same ext.name.
  $config_options << '-g'
end

task 'enable-profiler' do
  #to enable profiling run
  #rake build:profiler -- --with-profiler-dir=<path_to>/gperftools/'
  $config_options << '-p'
end

desc 'requires gcov and lcov in $PATH'
task 'report-coverage' do
  outdir = File.dirname(Dir['tmp/**/Makefile'].first)
  curdir = Dir.pwd
  Dir.chdir(outdir) do
    sh "lcov -c -i -d . -o kryptcore_base.info"
    Dir.entries("#{curdir}/ext/krypt/core").each do |f|
      next if File.directory? f || f !~ /\.[hc]$/
      # See http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=535755
      sh "gcov -o . #{f}"
    end
    sh "lcov -c -d . -o kryptcore.info"
    sh "lcov -a kryptcore.info -a kryptcore_base.info -o kryptcore_total.info"
    sh "lcov -r kryptcore_total.info ruby.h --output-file kryptcore_total.info"
    sh "lcov -r kryptcore_total.info '*include*' --output-file kryptcore_total.info"
    sh "genhtml -o coverage kryptcore_total.info"
  end
end

desc 'Build ext for coverage and generate a coverage report of spec.'
task 'coverage' => ['clean', 'enable-coverage', 'compile', 'spec-run', 'report-coverage']

desc 'Build and run RSpec code examples'
task 'spec' => ['compile', 'spec-run']

task :build => :compile

namespace :build do
  task :debug => ['enable-coverage', 'build']
  task :profiler => ['enable-profiler', 'build']
end
  
Rake::RDocTask.new("doc") do |rdoc|
  rdoc.rdoc_dir = 'doc'
  rdoc.title = "Krypt-Core API: Version #{Krypt::CORE_VERSION}"
  rdoc.rdoc_files.include('README.rdoc')
  rdoc.rdoc_files.include('ext/**/*')
end
