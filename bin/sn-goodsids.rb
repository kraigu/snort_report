#!/usr/bin/env ruby

# Port of perl script FindKnownGoodSIDs to Ruby, only allow/require the SIDs to be in a separate file
# Mike Patterson <mike.patterson@uwaterloo.ca> in his guise as an ISS staff member at uWaterloo
# 24 September 2012 

require 'snort_report.rb'
require 'mysql2'
require 'optparse'

options = {}

optparse = OptionParser.new do |opts|
	opts.banner = "Usage:"
	options[:filename] = nil
	opts.on('-f','--filename FILE',"Input config file") do |file|
		options[:filename] = file
	end
	options[:SID] = false
	opts.on('-s','--all-SID NUM',"SID to search for, format GID:SID with GID as optional (default to GID 1)") do |sid|
		options[:SID] = sid
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

begin
	if(options[:filename])
		file = options[:filename]
		myc = Snort_report.parseconfig(:a => file)
	else
		myc = Snort_report.parseconfig
	end
rescue
	abort("Huh, something went wrong retrieving your configuration file. Does it exist?")
end

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

gsids = Hash.new # Hash to hold each of our yummy valuable GID:SIDs

KGSIDFile = Snort_report.path

# variable assignment so later I can add code to make this a CLI arg
if (options[:SID])
    begin  
		sid = options[:SID]
	    if (sid =~ /:/)
	       gid = sid.split(":").first
	       sid = sid.split(":").last
	    else
	       gid = 1
	       sid = sid.split(":").last
	    end   	
		if( (sid.class == String) && !(sid.empty?))
			sid.strip!
			gsids[sid] = gid
			if(debug > 2)
				puts "Found GID:SID #{gsids[sid]} #{sid}\n"
			end
		end
	rescue => err
	abort "Uh oh SID file: #{err}"
	end
else
    begin
	    SIDF = File.open(KGSIDFile,"r")
	    while (line = SIDF.gets)
		    # throw away comments
		    tstring = line.split(/#/) # the SID, if any, should now be in [0]
	     	gidsid = tstring[0]
			if (gidsid =~ /:/)
	           gid = gidsid.split(":").first
	           sid = gidsid.split(":").last
	        else
	           gid = 1
	           sid = gidsid.split(":").last
	        end  		
		    if( (sid.class == String) && !(sid.empty?))
		    	sid.strip!
		    	gsids[sid] = gid
		    	if(debug > 2)
		    		puts "Found GID:SID #{gsids[sid]} #{sid}\n"
		    	end
		    end
	    end
    rescue => err
	    abort "Uh oh SID file: #{err}"
    end
end	

dbc = Snort_report.sqlconnect(myc)

gsids.each do |csid, gid|
	sql = %Q|SELECT e.cid,e.sid,timestamp as ts,INET_NTOA(ip_src) as ips,INET_NTOA(ip_dst) as ipd,
	sig_name as sidn,sig_rev as sidr,sig_gid as gidr
	FROM event e JOIN signature s ON e.signature = s.sig_id JOIN iphdr i ON i.cid = e.cid AND i.sid = e.sid
	WHERE s.sig_gid = #{gid} AND s.sig_sid = #{csid} AND e.timestamp LIKE '#{checkdate}%' ORDER BY timestamp;|
	results = Snort_report.query(dbc, sql)
	results.each do |row|
		puts "#{row["ts"]}\t#{row["sid"]}:#{row["cid"]}\t#{gid}:#{csid} #{row["sidr"]}\t#{row["ips"]}\t#{row["ipd"]}\t#{row["sidn"]}"
	end
end
