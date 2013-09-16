#!/usr/bin/env ruby

# Find all alerts for a given IP address
# Mike Patterson <mike.patterson@uwaterloo.ca> in his guise as an ISS staff member at uWaterloo
# 21 September 2012

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
	options[:ipaddress] = false
	opts.on('-i','--IP NUM',"Searching for the IP address") do |ip|
		options[:ipaddress] = ip
	end
	options[:time] = false
	opts.on('-d','--time NUM',"checktime") do |time|
		options[:time] = time
	end
	options[:ptime] = false
	opts.on('-p','--time',"Prior 24 hours") do
	options[:ptime] = true
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
if(options[:ptime])
    pdate = DateTime.now
    pdate -= 1
    pdate = pdate.strftime('%Y-%m-%d %H:%M')
end

if debug > 0
	dst = "Searching for #{sip}"
	if(!checktime.nil?)
		dst = dst + " for #{checktime}"
	end
	puts dst
end

dbc = Snort_report.sqlconnect(myc)

#randomly create an sequence number for temp table

sql = %Q|CREATE TEMPORARY TABLE IF NOT EXISTS temp_table (PRIMARY KEY(cid)) ENGINE=MEMORY
AS(
	SELECT cid, ip_src, ip_dst
	FROM iphdr WHERE ip_src = INET_ATON('#{sip}') OR ip_dst = INET_ATON('#{sip}')
);|

if debug > 0
	p sql
end

Snort_report.query(dbc, sql)

sql = %Q|SELECT event.cid,event.timestamp,signature.sig_sid,signature.sig_name,
INET_NTOA(temp_table.ip_src),INET_NTOA(temp_table.ip_dst)
FROM event JOIN signature on event.signature = signature.sig_id
JOIN temp_table on event.cid = temp_table.cid|

if(!checktime.nil?)
	sql = sql + %Q| WHERE event.timestamp LIKE '#{checktime}%' |
end

if(!pdate.nil?)
	sql = sql + %Q| WHERE event.timestamp > '#{pdate}%' |
end

sql = sql + %Q| ORDER BY event.timestamp;|

if debug > 0
	p sql
end

results = Snort_report.query(dbc, sql)

# want the print order to be timestamp, sequence, sid, source ip, dest ip, message text
headers = results.fields
results.each do |row|
 	puts "#{row["timestamp"]}\t#{row["cid"]}\t#{row["sig_sid"]}\t#{row["INET_NTOA(temp_table.ip_src)"]}\t#{row["INET_NTOA(temp_table.ip_dst)"]}\t#{row["sig_name"]}\n"
end
