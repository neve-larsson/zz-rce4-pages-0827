Jekyll::Hooks.register :site, :post_write do |site|
  File.write(File.join(site.dest, 'hd-plugin-marker.txt'), "HD-PLUGIN-EXECUTED ruby=#{RUBY_VERSION}\n")
end
