#!/usr/bin/env ruby

# Retrieve the payload for a given event ID
# Mike Patterson <mike.patterson@uwaterloo.ca> in his guise as an ISS staff member at uWaterloo
# 21 September 2012

require 'snort_report'
require 'mysql2'

debug = 0

begin
	myc = Snort_report.parseconfig
rescue
	abort("Huh, something went wrong retrieving your mysql config. Does it exist?")
end

pdata = Hash.new

snum = ARGV.shift
if(snum.nil?)
	abort("Requires a sequence number")
end

dbc = Mysql2::Client.new(
	:host => myc.get_value('client')['host'],
	:username => myc.get_value('client')['user'],
	:password => myc.get_value('client')['password'],
	:database => myc.get_value('mysql')['database'],
	)

# First find out if we need TCP, UDP, or ICMP
sql = %Q|SELECT ip_proto FROM iphdr JOIN event on iphdr.cid = event.cid
WHERE iphdr.cid = '#{snum}';|
begin
	results = dbc.query(sql)
rescue
	abort("IP protocol query died\n#{sql}")
end
proto = 0
results.each(:as => :array) do |row|
	proto = row[0]
end
if debug > 0
	puts "Protocol was #{proto}"
end

if (!( (proto == 1) || (proto == 6) || (proto == 17) ) )
	abort("Bad protocol #{proto}")
end

# Now get the actual data. Start setting up common parts.
sql = %Q|SELECT e.cid,e.timestamp,sig_name,sig_sid,sig_rev,INET_NTOA(ip_src),INET_NTOA(ip_dst),
|

pdata["proto"] = "none"
if(proto == 17)
	sql = sql + %Q|
 u.udp_sport,u.udp_dport
 FROM udphdr u JOIN iphdr i ON u.cid = i.cid
 JOIN event e ON u.cid = e.cid
 |
 pdata["proto"] = "UDP"
elsif(proto == 6)
	sql = sql + %Q|
 t.tcp_sport,t.tcp_dport
 FROM tcphdr t JOIN iphdr i ON t.cid = i.cid
 JOIN event e ON t.cid = e.cid
 |
 pdata["proto"] = "TCP"
else
	sql = sql + %Q|
 icmp.icmp_type,icmp.icmp_code
 FROM icmphdr icmp JOIN iphdr i ON icmp.cid = i.cid
 JOIN event e on i.cid = e.cid
 |
 pdata["proto"] = "ICMP"
end

sql = sql + %Q|
 JOIN signature s
 ON e.signature = s.sig_id
 WHERE e.cid = '#{snum}';
|

if debug > 0
	puts "SQL for 2:\n#{sql}\n"
end

begin
	results = dbc.query(sql)
rescue
	abort("Final query died\n#{sql}")
end

results.each(:as => :array) do |row|
	pdata["seq"] = row[0]
	pdata["ts"] = row[1]
	pdata["desc"] = row[2]
	pdata["sid"] = row[3]
	pdata["srev"] = row[4]
	pdata["sip"] = row[5]
	pdata["dip"] = row[6]
	pdata["sport"] = row[7]
	pdata["dport"] = row[8]
end

sql = %Q|SELECT data_payload FROM data WHERE cid = '#{snum}';|
begin
	results = dbc.query(sql)
rescue
	abort("Payload query died\n#{sql}")
end
results.each(:as => :array) do |row|
	pdata["payload"] = row[0].scan(/../).map { |pair| pair.hex.chr }.join
end

puts "Sequence: #{pdata["seq"]}\n"
puts "Timestamp: #{pdata["ts"]}\n"
puts "Signature: #{pdata["sid"]} Rev #{pdata["srev"]} | #{pdata["desc"]}\n"
puts "Source: #{pdata["sip"]}:#{pdata["sport"]}\n"
puts "Destination: #{pdata["dip"]}:#{pdata["dport"]}\n"
puts "Decoded payload (#{pdata["proto"]}):\n----\n"
puts "#{pdata["payload"]}\n----"
