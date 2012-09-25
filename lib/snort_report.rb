require 'parseconfig'

class Snort_report
	def self.parseconfig
		cname = (ENV['HOME'] + "/.my.cnf")
		# TODO check permissions on the .my.cnf file, should require 0400 or 0600
		myc = ParseConfig.new(cname)
		return myc
	end

	def self.ydate
		tdate = DateTime.now
		tdate -= 1
		return tdate.strftime('%Y-%m-%d')
	end
end
