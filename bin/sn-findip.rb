#!/usr/bin/env ruby

# Find all alerts for a given IP address
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

sip = ARGV.shift
if(sip.nil?)
	abort("Requires an IP address")
end
checktime = ARGV.shift

if debug > 0
	dst = "Searching for #{sip}"
	if(!checktime.nil?)
		dst = dst + " for #{checktime}"
	end
	puts dst
end

dbc = Mysql2::Client.new(
	:host => myc.get_value('client')['host'],
	:username => myc.get_value('client')['user'],
	:password => myc.get_value('client')['password'],
	:database => myc.get_value('mysql')['database'],
	)

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
