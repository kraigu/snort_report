#!/usr/bin/env ruby

# Port of perl script DailySummary to Ruby
# Mike Patterson <mike.patterson@uwaterloo.ca> in his guise as an ISS staff member at uWaterloo
# 25 September 2012 


require 'snort_report'
require 'mysql2'

debug = 0

begin
	myc = Snort_report.parseconfig
rescue
	abort("Huh, something went wrong retrieving your mysql config. Does it exist?")
end

daycheck = (ARGV[0] || Snort_report.ydate)

if(debug > 0)
	puts "Summarising #{daycheck}\n"
end

dbc = Mysql2::Client.new(
	:host => myc.get_value('client')['host'],
	:username => myc.get_value('client')['user'],
	:password => myc.get_value('client')['password'],
	:database => myc.get_value('mysql')['database'],
	)

sql = %Q|SELECT COUNT(sig_name) as 'SigCount',sig_sid,sig_name,sig_gid FROM signature 
JOIN event on event.signature = signature.sig_id 
WHERE event.timestamp LIKE '#{daycheck}%'
GROUP BY sig_name ORDER BY SigCount DESC;|

stime = DateTime.now
begin
	results = dbc.query(sql)
rescue
	abort("#{sql} query died")
end
etime = DateTime.now

results.each do |row|
	puts "#{row["SigCount"]}\t#{row["sig_gid"]}:#{row["sig_sid"]}\t#{row["sig_name"]}\n"
end

puts "Started query: #{stime}\nEnded query: #{etime}\n"

