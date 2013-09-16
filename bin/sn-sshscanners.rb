#!/usr/bin/env ruby

# Find SSH scans outbound and print out a CSV - SID is 2003068
# Mike Patterson <mike.patterson@uwaterloo.ca> in his guise as an ISS staff member at uWaterloo
# 25 September 2012 
# Optional arguments - a date value YYYY-[mm]-[dd]

require 'snort_report.rb'
require 'mysql2'
require 'optparse'
require 'securerandom'

options = {}

optparse = OptionParser.new do |opts|
	opts.banner = "Usage:"
	options[:filename] = nil
	opts.on('-f','--filename FILE',"Input config file or use default") do |file|
		options[:filename] = file	
	end
	options[:sdate] = false
	opts.on('-d','--date NUM',"Searching data on the date or default to yesterday") do |date|
		options[:sdate] = date
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

daycheck = (options[:sdate] || Snort_report.ydate) # Default to checking yesterday's data
puts daycheck

dbc = Snort_report.sqlconnect(myc)

# First get the internal sig_ids for the given SID. There SHOULD be only one, but you never know.
# Store the results in an array called rids
sql = %Q|SELECT sig_id FROM signature WHERE sig_sid = '2003068';|
rids = Snort_report.query(dbc, sql)
if(debug > 0)
	puts "Internal IDs for SSH outbound scan SID 2003068\n"
	rids.each(:as => :array) do |rid|
		p rid
	end
end

# Create a temp table, dirtier but easier than a subselect
#  for now?
sql = %Q|CREATE TEMPORARY TABLE IF NOT EXISTS temp_table1 (cid int(10) unsigned PRIMARY KEY, timestamp datetime);|
Snort_report.query(dbc, sql)

dcount = 1
rids.each(:as => :array) do |rid|
	if(debug > 1)
		puts "rids counter is #{dcount}"
	end
	# select the timestamp here to save us a later join
	sql = %Q|INSERT INTO temp_table1 (cid,timestamp) SELECT cid,timestamp FROM event WHERE event.signature = #{rid[0]}
	AND event.timestamp LIKE '#{daycheck}%';|
	if(debug > 1)
		puts "SQL for result IDs\n"
		p sql
	end
	Snort_report.query(dbc, sql)
	dcount += 1
end

# Now we have all the cids and their timestamps in the table temp_table1.

#Annoyingly, mysql doesn't support a temporary table being opened twice in one query
#so a second temporary table must be created
sql = %Q|CREATE TEMPORARY TABLE temp_table2 (PRIMARY KEY(cid)) AS (SELECT cid FROM temp_table1);|
Snort_report.query(dbc, sql)

sql = %Q|SELECT INET_NTOA(ip_src) AS sip,INET_NTOA(ip_dst) AS dip,timestamp
FROM iphdr JOIN temp_table1 ON iphdr.cid = temp_table1.cid
WHERE iphdr.cid IN (SELECT cid FROM temp_table2)
ORDER BY timestamp;|

results = Snort_report.query(dbc, sql)

results.each do |row|
	puts %Q|"#{row["sip"]}","#{row["dip"]}","#{row["timestamp"]}"|
end

