# frozen_string_literal: true
# Toolkit source MIT; installed Metasploit provides the RPC handlers on this private PTY.
require 'json'
require 'securerandom'
require 'msf/core/rpc/v10/service'

class ToolkitBridge
  def initialize(framework)
    @framework = framework
    @rpc = Msf::RPC::Service.new(framework)
    @identity = SecureRandom.uuid
    @prefix = "TOOLKIT/#{ENV.fetch('TOOLKIT_BRIDGE_NONCE')}/"
    @allowed = %w[core.version module.exploits module.auxiliary module.post module.payloads
                  module.encoders module.nops module.evasion module.info module.options module.search
                  module.encode_formats
                  module.execute module.compatible_payloads module.target_compatible_payloads
                  session.list session.stop session.shell_read session.shell_write
                  session.meterpreter_read session.meterpreter_write job.list job.info job.stop
                  console.create console.list console.read console.write console.destroy console.tabs]
  end

  def frame(value)
    encoded = JSON.generate(value)
    raise 'Response limit' if encoded.bytesize > 4 * 1024 * 1024
    STDOUT.write("\n#{@prefix}#{encoded}\n")
    STDOUT.flush
  end

  def run
    frame('v' => 1, 'type' => 'ready', 'id' => @identity, 'version' => Msf::Framework::Version)
    while (line = STDIN.gets(1024 * 1024 + 1))
      break unless line.end_with?("\n") && line.bytesize <= 1024 * 1024
      request = JSON.parse(line)
      id = request.fetch('id')
      begin
        method = request.fetch('method')
        args = request.fetch('args')
        raise 'Invalid request' unless request['v'] == 1 && args.is_a?(Array) && @allowed.include?(method)
        group, name = method.split('.', 2)
        Thread.current[:rpc_token] = @identity
        data = Timeout.timeout(15) { @rpc.handlers.fetch(group).public_send("rpc_#{name}", *args) }
        frame('v' => 1, 'type' => 'result', 'id' => id, 'data' => data)
      rescue StandardError
        frame('v' => 1, 'type' => 'error', 'id' => id, 'message' => 'Framework operation failed')
      ensure
        Thread.current[:rpc_token] = nil
      end
    end
  ensure
    # This is an owned console process. EOF means its supervisor is gone.
    Process.kill('TERM', Process.pid)
  end
end
