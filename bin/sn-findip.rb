#!/usr/bin/env ruby

# Find all alerts for a given IP address
# Mike Patterson <mike.patterson@uwaterloo.ca> in his guise as an ISS staff member at uWaterloo
# 21 September 2012

require 'snort_report'
require 'mysql2'
require 'optparse'

options = {}

optparse = OptionParser.new do |opts|
	opts.banner = "Usage:"
	options[:filename] = nil
	opts.on('-f','--filename FILE',"Input config file or use default") do |file|
		options[:filename] = file	
	end
	options[:ipaddress] = false
	opts.on('-i','--IP NUM',"Searching for the IP address") do |ip|
		options[:ipaddress] = ip
	end
	options[:time] = false
	opts.on('-d','--time NUM',"checktime") do |time|
		options[:time] = time
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
	abort("Huh, something went wrong retrieving your mysql config. Does it exist?")
end

if(!(options[:ipaddress]))
    abort("Requires an IP address")
else
    sip = options[:ipaddress]
end

if(options[:time])
checktime = options[:time]
end

if debug > 0
	dst = "Searching for #{sip}"
	if(!checktime.nil?)
		dst = dst + " for #{checktime}"
	end
	puts dst
end

dbc = Snort_report.sqlconnect(myc)

sql = %Q|CREATE TABLE IF NOT EXISTS fiptmp (cid int(10) unsigned PRIMARY KEY,
ip_src int(10) unsigned, ip_dst int(10) unsigned);|

begin
	results = dbc.query(sql)
rescue
	abort("Query died at creating fiptmp\n#{sql}")
end

sql = %Q|DELETE FROM fiptmp;|
begin
	results = dbc.query(sql)
rescue
	abort("#{sql} query died")
end

sql = %Q|INSERT INTO fiptmp (cid,ip_src,ip_dst) SELECT cid, ip_src, ip_dst
FROM iphdr WHERE ip_src = INET_ATON('#{sip}') OR ip_dst = INET_ATON('#{sip}');|

if debug > 0
	p sql
end

begin
	results = dbc.query(sql)
rescue
	abort("Query died at insert into fiptmp\n#{sql}")
end

sql = %Q|SELECT event.cid,event.timestamp,signature.sig_sid,signature.sig_name,
INET_NTOA(fiptmp.ip_src),INET_NTOA(fiptmp.ip_dst)
FROM event JOIN signature on event.signature = signature.sig_id
JOIN fiptmp on event.cid = fiptmp.cid|

if(!checktime.nil?)
	sql = sql + %Q| WHERE event.timestamp LIKE '#{checktime}%' |
end
sql = sql + %Q| ORDER BY event.timestamp;|

if debug > 0
	p sql
end

begin
	results = dbc.query(sql)
rescue
	abort("Query died at select\n#{sql}")
end

# want the print order to be timestamp, sequence, sid, source ip, dest ip, message text
headers = results.fields
results.each do |row|
 	puts "#{row["timestamp"]}\t#{row["cid"]}\t#{row["sig_sid"]}\t#{row["INET_NTOA(fiptmp.ip_src)"]}\t#{row["INET_NTOA(fiptmp.ip_dst)"]}\t#{row["sig_name"]}\n"
end

sql = %Q|DROP TABLE fiptmp;|
dbc.query(sql)