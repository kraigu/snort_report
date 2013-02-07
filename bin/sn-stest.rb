#!/usr/bin/env ruby

# Just a simple test to connect to the database and get a couple of values.

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
	opts.on('-h','--help') do
		puts opts
		exit
	end
end

optparse.parse!

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

stime = DateTime.now
dbc = Snort_report.sqlconnect(myc)
ctime = DateTime.now
sql = "SELECT COUNT(*) FROM event;"

begin
	results = dbc.query(sql)
rescue
	abort("#{sql} query died")
end

results.each do |row|
	puts "Event count: #{row["COUNT(*)"]}"
end
etime = DateTime.now

puts "Started:\t#{stime}\nConnected:\t#{ctime}\nEnded:\t\t#{etime}"

