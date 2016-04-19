#!/usr/bin/env ruby

# Retrieve the payload for a given event ID
# Mike Patterson <mike.patterson@uwaterloo.ca> in his guise as an ISS staff member at uWaterloo
# 21 September 2012 - 14 January 2013

require 'snort_report'
require 'mysql2'
require 'optparse'

options = {}

optparse = OptionParser.new do |opts|
	opts.banner = "Usage:"
	options[:filename] = nil
	opts.on('-f','--filename FILE',"Configuration file path (default ~/.srrc)") do |file|
		options[:filename] = file	
	end
	options[:seq] = false
	opts.on('-s','--sequence NUM',"Sequence Number for which to search, Format sid:cid") do |s|
		options[:seq] = s
	end	
	options[:verbose] = 0
	opts.on('-v','--verbose NUM',Integer,"Verbosity(Debug)") do |v|
		options[:verbose] = v
	end
	opts.on('-h','--help') do
		puts opts
		exit
	end
end

optparse.parse!

debug = options[:verbose]

begin
	if(options[:filename])
	    file = options[:filename]
        myc= Snort_report.parseconfig(:a => file)
    else
        myc = Snort_report.parseconfig
    end
rescue
	abort("Huh, something went wrong retrieving your configuration file. Does it exist?")
end

pdata = Hash.new

if(!(options[:seq]))
    abort "Requires a sequence number"
else
    snum = options[:seq]
end

pdata["seq"] = snum;
sid = snum.split(':')[0]
cid = snum.split(':')[1]

dbc = Snort_report.sqlconnect(myc)

# First find out if we need TCP, UDP, or ICMP. Get the IP addresses while we're here.
sql = %Q|SELECT ip_proto,INET_NTOA(ip_src),INET_NTOA(ip_dst) FROM iphdr WHERE iphdr.cid = '#{cid}' AND iphdr.sid = '#{sid}';|
if( debug > 0 )
	puts "Protocol query is\n#{sql}\n"
end
stime = Time.now
results = Snort_report.query(dbc, sql)
dtime = Time.now - stime
if( debug > 1 )
	puts "Protocol query took #{dtime} seconds\n"
end

proto = 0
results.each(:as => :array) do |row|
	proto = row[0]
	pdata["sip"] = row[1]
	pdata["dip"] = row[2]
end
if debug > 0
	puts "Protocol was #{proto}"
end

# if (!( (proto == 1) || (proto == 6) || (proto == 17) ) )
# 	abort("Bad protocol #{proto}")
# end

# Now get the actual data. Start setting up common parts.
# This used to be a massive JOIN:
# SELECT e.cid,e.timestamp,sig_name,sig_gid,sig_sid,sig_rev,INET_NTOA(ip_src),INET_NTOA(ip_dst),
# (check on protocol but usually) 
# t.tcp_sport,t.tcp_dport FROM tcphdr t JOIN iphdr i ON t.cid = i.cid JOIN event e ON t.cid = e.cid
# JOIN signature s ON e.signature = s.sig_id WHERE e.cid = '#{snum}';
# but joins are dumb with indexes.
# So instead I'm going to copy and paste code unnecessarily in the interest of current-expediency.
# Leave me alone, it's after 5 on a Friday.

sql = %Q|SELECT timestamp,signature FROM event WHERE cid = #{cid} AND sid = #{sid};|
if(debug > 0)
	puts "Events query sql is\n#{sql}\n"
end
stime = Time.now
results = Snort_report.query(dbc, sql)
dtime = Time.now - stime
if( debug > 1 )
	puts "Events query took #{dtime} seconds\n"
end
results.each(:as => :array) do |row|
	pdata["ts"] = row[0]
	pdata["esig"] = row[1]
end

sql = %Q|SELECT sig_name,sig_gid,sig_sid,sig_rev FROM signature WHERE sig_id = #{pdata["esig"]};|
stime = Time.now
results = Snort_report.query(dbc, sql)
dtime = Time.now - stime
if( debug > 1 )
	puts "Signature query took #{dtime} seconds\n"
end
results.each(:as => :array) do |row|
	pdata["desc"] = row[0]
	pdata["gid"] = row[1]
	pdata["sid"] = row[2]
	pdata["srev"] = row[3]
end	

pdata["proto"] = "other"
if(proto == 17)
        sql = %Q|SELECT udp_sport,udp_dport FROM udphdr WHERE cid = #{cid} AND sid = #{sid};|
        pdata["proto"] = "UDP"
elsif(proto == 6)
        sql = %Q|SELECT tcp_sport,tcp_dport FROM tcphdr WHERE cid = #{cid} AND sid = #{sid};|
		pdata["proto"] = "TCP"
elsif(proto == 1)
        sql = %Q|SELECT icmp_type,icmp_code FROM icmphdr WHERE cid = #{cid} AND sid = #{sid};|
		pdata["proto"] = "ICMP"
end

if ( (proto == 1) || (proto == 6) || (proto == 17) )
	stime = Time.now
	results = Snort_report.query(dbc, sql)
	dtime = Time.now - stime
	if( debug > 1 )
		puts "Ports query took #{dtime} seconds\n"
	end
	results.each(:as => :array) do |row|
		pdata["sport"] = row[0]
		pdata["dport"] = row[1]
	end

	sql = %Q|SELECT data_payload FROM data WHERE cid = '#{cid}' AND sid = '#{sid}';|
	stime = Time.now
	results = Snort_report.query(dbc, sql)
	dtime = Time.now - stime
	if( debug > 1 )
		puts "Payload query took #{dtime} seconds\n"
	end
	results.each(:as => :array) do |row|
		pdata["payload"] = row[0].scan(/../).map { |pair| pair.hex.chr }.join
	end
else
	pdata["payload"] = '<Nil>'
end

puts "Sequence: #{pdata["seq"]}\n"
puts "Timestamp: #{pdata["ts"]}\n"
puts "Signature: #{pdata["sid"]} Rev #{pdata["srev"]} (GID #{pdata["gid"]}) | #{pdata["desc"]}\n"
puts "Source: #{pdata["sip"]}:#{pdata["sport"]}\n"
puts "Destination: #{pdata["dip"]}:#{pdata["dport"]}\n"
puts "Decoded payload (#{pdata["proto"]}):\n----\n"
puts "#{pdata["payload"]}\n----"
