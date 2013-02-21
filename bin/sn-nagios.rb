#!/usr/bin/env ruby

# Callable by Nagios to check to see when the most recent database updates were
# Mike Patterson <mike.patterson@uwaterloo.ca> in his guise as an ISS staff member at uWaterloo
# 13 December 2012 


require 'snort_report'
require 'mysql2'
require 'optparse'

options = {}

optparse = OptionParser.new do |opts|
	options[:warn] = 60
	opts.on('-w','--warning NUM',Integer,"Warning value in seconds") do |w|
		options[:warn] = w
	end
	options[:filename] = nil
	opts.on('-f','--filename FILE',"Input config file") do |file|
		options[:filename] = file
	end
	options[:critical] = 300
	opts.on('-c','--critical NUM',Integer,"Critical value in seconds") do |c|
		options[:critical] = c
	end
	options[:verbose] = 0
	opts.on('-v','--verbose NUM',Integer,"Verbosity") do |v|
		options[:verbose] = v
	end
	opts.on('-h','--help') do
		puts opts
		exit
	end
end.parse!

verbose = options[:verbose]

if(verbose) > 0
	options.each do |o|
		p o
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
	abort("Huh, something went wrong retrieving your mysql config. Does it exist?")
end

dbc = Snort_report.sqlconnect(myc)

sql = %Q|SELECT max(timestamp) AS mts FROM event;|

stime = Time.now
begin
	results = dbc.query(sql)
rescue
	abort("#{sql} query died")
end
etime = Time.now

mts = Time.new
results.each do |row| # should only have one row...
	mts = row["mts"]
end

dtime = etime - mts

if(dtime > options[:critical])
	puts "CRITICAL: #{dtime} seconds"
	exit 2
elsif(dtime > options[:warn])
	puts "WARNING: #{dtime} seconds"
	exit 1
else
	puts "OK: #{dtime}"
end

if(verbose > 0)
	puts "Started query: #{stime}\nEnded query: #{etime}\n"
end
