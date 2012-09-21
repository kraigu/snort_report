Gem::Specification.new do |s|
	s.name		= "snort_report"
	s.version	= "0.1.1"
	s.date		= "2012-09-21"
	s.summary	= "Snort Report"
	s.description = "Gem to ease reporting from Snort SQL databases"
	s.authors	= ["Mike Patterson"]
	s.email		= 'mike.patterson@uwaterloo.ca'
	s.files		= ["lib/snort_report.rb"]
	s.requirements << 'A functional Snort database, tested with MySQL, mysql2 and ParseConfig gems'
	s.executables << 'SSHScanSum.rb'
	s.executables << 'sn-findip.rb'
	s.executables << 'sn-payload.rb'
end
