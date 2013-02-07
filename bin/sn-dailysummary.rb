#!/usr/bin/env ruby

# Port of perl script DailySummary to Ruby
# Mike Patterson <mike.patterson@uwaterloo.ca> in his guise as an ISS staff member at uWaterloo
# 25 September 2012 

require 'snort_report'
require 'mysql2'
require 'optparse'

options = {}

optparse = OptionParser.new do |opts|
	opts.banner = "Usage:"
	options[:filename] = nil
	opts.on('-f','--filename FILE',"Input config file") do |file|
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

daycheck = (options[:sdate] || Snort_report.ydate)

if(debug > 0)
	puts "Summarising #{daycheck}\n"
end

dbc = Snort_report.sqlconnect(myc)

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