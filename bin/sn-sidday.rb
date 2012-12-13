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

require 'snort_report'
require 'mysql2'

debug = 0

if( !(ARGV[0]) )
	abort "Search for which SID?"
else
	ssid = ARGV[0]
end

begin
	myc = Snort_report.parseconfig
rescue
	abort("Huh, something went wrong retrieving your mysql config. Does it exist?")
end

if(ARGV[1])
	sdate = ARGV[1]
else
	sdate = DateTime.now.strftime('%Y-%m-%d')
end

if(debug > 0)
	puts "Searching for #{ssid} on #{sdate}\n"
end

dbc = Mysql2::Client.new(
	:host => myc.get_value('client')['host'],
	:username => myc.get_value('client')['user'],
	:password => myc.get_value('client')['password'],
	:database => myc.get_value('mysql')['database'],
	)

# get the internal signature IDs of the snort SID that was requested.
# this is to save a join later.
sql = %Q|SELECT sig_id,sig_rev,sig_name FROM signature WHERE sig_sid = #{ssid};|
begin
	rids = dbc.query(sql)
rescue
	abort("#{sql} query died")
end
if (debug > 0)
	puts "Signature information\n"
	rids.each(:as => :array) do |row|
		p row
	end
end

sql = %Q|SELECT e.cid,timestamp as ts,INET_NTOA(ip_src) as ips,INET_NTOA(ip_dst) as ipd,
	sig_name as sidn,sig_rev as sidr
	FROM event e JOIN signature s ON e.signature = s.sig_id JOIN iphdr i ON i.cid = e.cid
	WHERE s.sig_sid = #{ssid} AND e.timestamp LIKE '#{sdate}%' ORDER BY timestamp;|
if(debug > 0)
	p sql
end
begin
	results = dbc.query(sql)
rescue
	abort("#{sql} query died")
end

# some machinations to make output match sn-goodsids - eventually I'll make an alert class
# with a prettyprint method
results.each(:as => :array) do |row|
	puts "#{row[1]}\t#{row[0]}\t#{ssid}\t#{row[5]}\t#{row[2]}\t#{row[3]}\t#{row[4]}"
end

