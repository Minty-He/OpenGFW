#!/bin/ruby
require 'json'
require 'socket'

server = TCPServer.new 23333
loop do
  Thread.start server.accept do |client|
    data = client.gets
    puts "data recived:#{data}"
    tuple = JSON.parse data
    ip_blocked = tuple['src_ip']
    system "ip route add blackhole #{ip_blocked}/32"
    puts "#{ip_blocked} has been blocked."
    client.close
  end
end
