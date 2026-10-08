# frozen_string_literal: true
# Toolkit source: MIT. Runs inside the independently installed Metasploit runtime.
require 'json'
require 'securerandom'
require 'msfenv'
require 'msf/base'
require 'msf/core/rpc/v10/service'

STDOUT.sync = true
line = STDIN.gets(16_385)
raise 'Invalid startup envelope' unless line && line.bytesize <= 16_384 && line.end_with?("\n")
settings = JSON.parse(line)
password = settings.fetch('password')
raise 'Invalid password length' unless password.is_a?(String) && password.length.between?(1, 4096)
framework = Msf::Simple::Framework.create('DisableDatabase' => true)
instance = SecureRandom.uuid
identity = Object.new
identity.define_singleton_method(:rpc_identity) do
  { 'id' => instance, 'version' => Msf::Framework::Version }
end
service = Msf::RPC::Service.new(
  framework, host: '127.0.0.1', port: Integer(settings.fetch('port')), uri: '/api/',
  ssl: true, cert: settings.fetch('certificate'), token_timeout: 300,
  dispatcher_timeout: 15, users: [[settings.fetch('username'), password]]
)
service.add_handler('toolkit', identity)
%w[TERM INT].each { |sig| Signal.trap(sig) { exit } }
begin
  service.start
  puts JSON.generate('ready' => true, 'instance_id' => instance)
  # The supervisor owns this pipe. Its death must not leave a daemon running.
  Thread.new { STDIN.read; Process.kill('TERM', Process.pid) }
  service.wait
ensure
  service.stop if service.service
  framework.jobs.each_pair { |_id, job| job.stop }
end
