require 'parseconfig'

class Snort_report
	def self.parseconfig(opts={})
	    o = {
                :a =>(ENV['HOME'] + "/.srrc"),
            }.merge(opts)
        cname = "#{o[:a]}" 
        permission = File.stat(cname).mode.to_s(8)[2..5]
		if(permission == '0600' or permission == '0400') 
		  myc = ParseConfig.new(cname)
		  return myc
		end
	end

	def self.ydate
		tdate = DateTime.now
		tdate -= 1
		return tdate.strftime('%Y-%m-%d')
	end
	
	def self.sqlconnect(myc)
		dbc = Mysql2::Client.new(
			:host => myc.get_value('client')['host'],
			:username => myc.get_value('client')['user'],
			:password => myc.get_value('client')['password'],
			:database => myc.get_value('mysql')['database'],
		)
		return dbc
	end
	def self.path
	    myc = Snort_report.parseconfig
	    location = myc.get_value('file')['path']
		return location
	end	
end



