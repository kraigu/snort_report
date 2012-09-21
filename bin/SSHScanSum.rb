#!/usr/bin/env ruby

# /etc/networks had better exist and be useful
# Input should be a file output from FindSSHScanners.pl, that is:
# quote delimited, comma separated text file format:
# "Source IP","Destination IP","timestamp"
# must be sorted by timestamp

# Possibility for later development:
# add optparse/date requirement and parse dates better.
#  http://blog.segment7.net/2008/01/05/optionparser-argument-casting
# One oddity: if you want an option to be anything other than TrueClass, you seem to
#  need to make the argument mandatory (see -c and -f)

require 'netaddr'
require 'csv'
require 'time'
require 'optparse'

options = {}

optparse = OptionParser.new do |opts|
	opts.banner = "Usage blah -f filename"
	options[:alldest] = false
	opts.on('-d','--all-dest',"All destination IPs") do
		options[:alldest] = true
	end
	options[:allsource] = false
	opts.on('-s','--all-source',"All source IPs") do
		options[:allsource] = true
	end
	options[:filename] = ""
	opts.on('-f','--filename FILE',"Input file (CSV), mandatory") do |file|
		options[:filename] = file
	end
	options[:summary] = false
	opts.on('-S','--summary',"Summarise output") do
		options[:summary] = true
	end
	options[:cutoff] = 1
	opts.on('-c','--cutoff NUM',Integer,"Cutoff value") do |c|
		options[:cutoff] = c
	end
	opts.on('-h','--help') do
		puts opts
		exit
	end
end

optparse.parse!

RNCIDRs = [ ]
# Blank array to hold our list of CIDRs for ResNet
TestCIDRs = [ NetAddr::CIDR.create('25.0.0.0/8') ]
# Fixed list of test remote nets: MoD
BadActors = {}
# Blank hash to eventually hold key=source IP, value = hash keyed on dest IP values array of count, timestamp

## FUNCTIONS
def parseRN(line)
	tmpl = line.split("\s")
	return tmpl[1] + tmpl[5]
end

def checkRN(arg)
	RNCIDRs.each do |t|
		if (t.contains?("#{arg}"))
			return 1
		end
	end
	return 0
end

def checkRemoteWant(arg)
	TestCIDRs.each do |t|
		if (t.contains?("#{arg}"))
			return 1
		end
	end
	return 0
end

## MAIN
# Read in and parse the networks file to find ResNet ranges
netfile = File.new("/etc/networks", "r")

while (netline = netfile.gets)
	if( (netline.include?"129.97") && ( (netline.include?"rn-") || (netline.include?"RESNET") ) )
		netline = parseRN(netline) # turn it into a CIDR string
		t = NetAddr::CIDR.create(netline)
		RNCIDRs.push t
	end
end

# Now parse the CSV named in the arguments
CSV.foreach(options[:filename]) do |row|
	# 0 = src, 1 = dst, 2 = ts
	# First, check to see if the source IP is in our list of ResNet CIDRs
	next if ( (options[:allsource] == false) && (checkRN(row[0]) == 0) )
	next if ( (options[:alldest] == false) && (checkRemoteWant(row[1]) == 0) )
	
	# Then see if we have a key already
	if ( BadActors.has_key?("#{row[0]}") )
		if ( BadActors[row[0]].has_key?(row[1]) ) # this never seems to get called
			BadActors[row[0]][row[1]][0] += 1
			BadActors[row[0]][row[1]][1] = row[2]
			# we already have an entry for this remote IP, update count and TS
		else
			# create a new row in the array for this remote IP, set count to 1 and TS
			nhash = { row[1] => [1,row[2]] }
			BadActors[row[0]] = BadActors[row[0]].merge(nhash)
		end
	else
		BadActors[row[0]] = {row[1] => [1,row[2]]}
	end
end

if ( !(options[:summary]) )
	puts '"Source","Destination","Count","Last Timestamp"'
	BadActors.keys.each do |rni|
		# rni will contain a string, the resnet IP, which is the key for BadActors
		BadActors[rni].each do |t|
			next if ( (BadActors[rni].size < options[:cutoff]) )
			# t will contain a hash, keys are MOD IPs
			# t[0] is a string, MOD IP
			# t[1] is an array, t[1][0] is Fixnum hit count, t[1][1] is timestamp
			puts "\"#{rni}\",\"#{t[0]}\",\"#{t[1][0]}\",\"#{t[1][1]}\""
		end
	end
else
	op = "Summary of SSH scanners:"
	if ( options[:allsource] )
		op = op + " all source IPs"
	else
		op = op + " ResNet source only"
	end
	if ( options[:alldest] )
		op = op + ", all destination IPs"
	else
		op = op + ", MoD destinations only"
	end
	puts "#{op}"
	BadActors.keys.each do |rni|
		next if ( (BadActors[rni].size < options[:cutoff]) )
		# rni is a hash, also a key		
		os = "Source: #{rni}, Unique Destinations #{BadActors[rni].size}, Last time"
		lts = Time.parse('1990-1-1 00:00:00')
		BadActors[rni].each do |t|
			ts = Time.parse(t[1][1])
			if ( ts > lts)
				lts = ts
			end
		end
		puts "#{os} #{lts}"
	end
end
