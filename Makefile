all:
	gem build snort_report.gemspec

clean:
	rm snort_report-0.1.1.gem
	rm *~

test: all clean
