#!/usr/bin/env ruby

# Port of perl script SnortGetSIDDay to Ruby
# Mike Patterson <mike.patterson@uwaterloo.ca> in his guise as an ISS staff member at uWaterloo
# 24 September 2012 

# Comments also ported...
# Should be able to get rid of the gsdtmp table altogether
# the string comparison on the datetime thing is horrible
# 
# 16:10 <[> http://stackoverflow.com/questions/2758486/mysql-compare-date-string-with-string-from-datetime-field
# 16:10 <[> so use DATE_FORMAT?
# 16:10 <[> but then I need to parse the argument to see if I've been passed a 
#           year, a year-month, or a year-month-day
# This version fixes a long-standing bug, wherein a given SID might have multiple revisions...
# Another bug: I assume gid = 1. In situations where there is duplication of sids amongst differing gids,
#  behaviour is undefined but probably bad.

require 'snort_report.rb'
require 'mysql2'
require 'optparse'

options = {}

optparse = OptionParser.new do |opts|
	opts.banner = "Usage:"
	options[:SID] = false
	opts.on('-s','--all-SID NUM',"SID to search for, format GID:SID with GID as optional (default to GID 1)") do |sid|
		options[:SID] = sid
	end
	options[:filename] = nil
	opts.on('-f','--filename FILE',"Configuration file path (default ~/.srrc)") do |file|
		options[:filename] = file
	end
	options[:sdate] = false
	opts.on('-d','--date NUM',"Date to search for, defaults to today") do |date|
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

if(!(options[:SID]))
    abort "Search for which SID?"
else
    ssid = options[:SID]
	if (ssid =~ /:/)
	   gid = ssid.split(":").first
	   ssid = ssid.split(":").last
	else
	   gid = 1
	   ssid = ssid.split(":").last
	end   
end

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

if(options[:sdate])
    sdate = options[:sdate]
else
    sdate = DateTime.now.strftime('%Y-%m-%d')
end	

if(debug > 0)
	puts "Searching for #{ssid} on #{sdate}\n"
end

dbc = Snort_report.sqlconnect(myc)

# get the internal signature IDs of the snort SID that was requested.
# this is to save a join later.
sql = %Q|SELECT sig_id,sig_rev,sig_name FROM signature WHERE sig_sid = #{ssid};|
rids = Snort_report.query(dbc, sql)
if (debug > 0)
	puts "Signature information\n"
	rids.each(:as => :array) do |row|
		p row
	end
end

sql = %Q|SELECT e.cid as cid,e.sid as sid,timestamp as ts,INET_NTOA(ip_src) as ips,INET_NTOA(ip_dst) as ipd,
	sig_name as sidn,sig_rev as sidr,sig_gid as gidr 
	FROM event e JOIN signature s ON e.signature = s.sig_id JOIN iphdr i ON i.cid = e.cid AND i.sid = e.sid
	WHERE s.sig_gid = #{gid} AND s.sig_sid = #{ssid} AND e.timestamp LIKE '#{sdate}%' ORDER BY timestamp;|

if(debug > 0)
	p sql
end
results = Snort_report.query(dbc, sql)

# some machinations to make output match sn-goodsids - eventually I'll make an alert class
# with a prettyprint method
results.each do |row|
	puts "#{row["ts"]}\t#{row["sid"]}:#{row["cid"]}\t#{ssid}\t#{row["sidr"]}\t#{row["ips"]}\t#{row["ipd"]}\t#{row["gidr"]}"
end
