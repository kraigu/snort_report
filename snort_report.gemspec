Gem::Specification.new do |s|
	s.name		= "snort_report"
	s.version	= "0.1.6"
	s.date		= "2012-11-19"
	s.summary	= "Snort Report"
	s.description = "Gem to ease reporting from Snort SQL databases"
	s.authors	= ["Mike Patterson"]
	s.email		= 'mike.patterson@uwaterloo.ca'
	s.files		= ["lib/snort_report.rb"]
	s.homepage	= "https://github.com/kraigu/snort_report"
	s.requirements << 'A functional MySQL Snort database with barnyard2 schema, mysql2 and ParseConfig gems'
	s.executables << 'SSHScanSum.rb'
	s.executables << 'sn-findip.rb'
	s.executables << 'sn-payload.rb'
	s.executables << 'sn-goodsids.rb'
	s.executables << 'sn-sidday.rb'
	s.executables << 'sn-dailysummary.rb'
	s.executables << 'sn-sshscanners.rb'
end
