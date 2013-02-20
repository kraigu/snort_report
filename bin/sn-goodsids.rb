#!/usr/bin/env ruby

# Port of perl script FindKnownGoodSIDs to Ruby, only allow/require the SIDs to be in a separate file
# Mike Patterson <mike.patterson@uwaterloo.ca> in his guise as an ISS staff member at uWaterloo
# 24 September 2012 

require '/home/cjshi/snort_report.rb'
require 'mysql2'
require 'optparse'

options = {}

optparse = OptionParser.new do |opts|
	opts.banner = "Usage:"
	options[:filename] = nil
	opts.on('-f','--filename FILE',"Input config file or use default") do |file|
		options[:filename] = file	
	end
	options[:sdate] = false
	opts.on('-d','--date NUM',"Searching data on the date or default to now") do |date|
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

if(options[:sdate])
	checkdate = options[:sdate]
else
	checkdate = DateTime.now.strftime('%Y-%m-%d')
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

gsids = Array.new # Array to hold each of our yummy valuable SIDs

KGSIDFile = Snort_report.path

# variable assignment so later I can add code to make this a CLI arg
begin
	SIDF = File.open(KGSIDFile,"r")
	while (line = SIDF.gets)
		# throw away comments
		tstring = line.split(/#/) # the SID, if any, should now be in [0]
		sid = tstring[0]
		if( (sid.class == String) && !(sid.empty?))
			sid.strip!
			gsids.push(sid)
			if(debug > 2)
				puts "Found SID #{sid}\n"
			end
		end
	end
rescue => err
	abort "Uh oh SID file: #{err}"
end

dbc = Snort_report.sqlconnect(myc)

gsids.each do |csid|
	sql = %Q|SELECT e.cid,timestamp as ts,INET_NTOA(ip_src) as ips,INET_NTOA(ip_dst) as ipd,
	sig_name as sidn,sig_rev as sidr
	FROM event e JOIN signature s ON e.signature = s.sig_id JOIN iphdr i ON i.cid = e.cid
	WHERE s.sig_sid = #{csid} AND e.timestamp LIKE '#{checkdate}%' ORDER BY timestamp;|

	begin
		results = dbc.query(sql)
	rescue
		abort("#{sql} query died")
	end

	results.each do |row|
		puts "#{row["ts"]}\t#{row["cid"]}\t#{csid} #{row["sidr"]}\t#{row["ips"]}\t#{row["ipd"]}\t#{row["sidn"]}"
	end
end