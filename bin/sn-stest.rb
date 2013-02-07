#!/usr/bin/env ruby

# Just a simple test to connect to the database and get a couple of values.

require 'snort_report'
require 'mysql2'

begin
	myc = Snort_report.parseconfig
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
