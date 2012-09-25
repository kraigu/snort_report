#!/usr/bin/env ruby

# Find SSH scans outbound and print out a CSV - SID is 2003068
# Mike Patterson <mike.patterson@uwaterloo.ca> in his guise as an ISS staff member at uWaterloo
# 25 September 2012 
# Optional arguments - a date value YYYY-[mm]-[dd]

require 'snort_report'
require 'mysql2'

debug = 0

begin
	myc = Snort_report.parseconfig
rescue
	abort("Huh, something went wrong retrieving your mysql config. Does it exist?")
end

daycheck = (ARGV[0] || Snort_report.ydate) # Default to checking yesterday's data

dbc = Mysql2::Client.new(
	:host => myc.get_value('client')['host'],
	:username => myc.get_value('client')['user'],
	:password => myc.get_value('client')['password'],
	:database => myc.get_value('mysql')['database'],
	)

# First get the internal sig_ids for the given SID. There SHOULD be only one, but you never know.
# Store the results in an array called rids
sql = %Q|SELECT sig_id FROM signature WHERE sig_sid = '2003068';|
begin
	rids = dbc.query(sql)
rescue
	abort("#{sql} query died")
end
if(debug > 0)
	puts "Internal IDs for SSH outbound scan SID 2003068\n"
	rids.each(:as => :array) do |rid|
		p rid
	end
end

# Create a temp table, dirtier but easier than a subselect
#  for now?
sql = %Q|CREATE TABLE IF NOT EXISTS sr_osshtmp (cid int(10) unsigned PRIMARY KEY, timestamp datetime);|
begin
	dbc.query(sql)
rescue Mysql2::Error
	abort("#{sql} query died, message was\n#{$!}\n")
end
$sql = %Q|DELETE FROM sr_osshtmp;|
begin
	dbc.query(sql)
rescue
	abort("#{sql} query died")
end

dcount = 1
rids.each(:as => :array) do |rid|
	if(debug > 1)
		puts "rids counter is #{dcount}"
	end
	# select the timestamp here to save us a later join
	sql = %Q|INSERT INTO sr_osshtmp (cid,timestamp) SELECT cid,timestamp FROM event WHERE event.signature = #{rid[0]}
	AND event.timestamp LIKE '#{daycheck}%';|
	if(debug > 1)
		puts "SQL for result IDs\n"
		p sql
	end
	begin
		dbc.query(sql)
	rescue Mysql2::Error
		abort("#{sql} query died, message was\n#{$!}\n")
	end
	dcount += 1
end

# Now we have all the cids and their timestamps in the table sr_osshtmp.

sql = %Q|SELECT INET_NTOA(ip_src) AS sip,INET_NTOA(ip_dst) AS dip,timestamp
FROM iphdr JOIN sr_osshtmp ON iphdr.cid = sr_osshtmp.cid
WHERE iphdr.cid IN (SELECT cid FROM sr_osshtmp)
ORDER BY timestamp;|
begin
	results = dbc.query(sql)
rescue Mysql2::Error
	abort("#{sql} query died, message was\n#{$!}\n")
end

results.each do |row|
	puts %Q|"#{row["sip"]}","#{row["dip"]}","#{row["timestamp"]}"|
end

sql = %Q|DROP TABLE sr_osshtmp;|
begin
	dbc.query(sql)
rescue Mysql2::Error
	abort("#{sql} query died, message was\n#{$!}\n")
end
