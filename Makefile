all:
	gem build snort_report.gemspec

clean:
	rm snort_report-*.gem
	rm *~

test: all clean
