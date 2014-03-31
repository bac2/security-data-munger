from django.core.management.base import BaseCommand, CommandError
from datamunger.models import Vulnerability, Application
import urllib2
from bs4 import BeautifulSoup
from optparse import make_option

class Command(BaseCommand):

	option_list = BaseCommand.option_list + (
		make_option('--initialise',
			action='store_true',
			dest='initialise',
			default=False,
			help='Pulls entire history'),
		)

	def handle(self, *args, **options):

		urls = [
			'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-modified.xml'
		]

		if options['initialise']:
			urls = [
				'http://users.ecs.soton.ac.uk/temt1g10/temp.xml',
	#			'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2002.xml',	
	#			'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2003.xml',	
	#			'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2004.xml',	
	#			'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2005.xml',	
	#			'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2006.xml',	
	#			'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2007.xml',	
	#			'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2008.xml',	
	#			'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2009.xml',	
	#			'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2010.xml',	
	#			'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2011.xml',	
	#			'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2012.xml',	
	#			'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2013.xml',	
	#			'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2014.xml'

		]

		for url in urls:
			page = urllib2.urlopen(url)
			soup = BeautifulSoup(page.read())
			entry = soup.find_all('entry')

			for e in entry:
				cve = e.find('vuln:cve-id').string
				summary = e.find('vuln:summary').string
				v = Vulnerability(cve=cve,summary=summary)
				v.save()
				software = e.find_all('vuln:product')
				for product in software:
					a = Application(name=product.string,vulnerability=v)
					a.save()
