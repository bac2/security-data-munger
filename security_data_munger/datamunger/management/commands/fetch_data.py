from django.core.management.base import BaseCommand, CommandError
from datamunger.models import Vulnerability, Application, Reference
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
			print 'Checking ' + url

			page = urllib2.urlopen(url)
			soup = BeautifulSoup(page.read())
			entry = soup.find_all('entry')

			for e in entry:
				cve = e.find('vuln:cve-id').string
				summary = e.find('vuln:summary').string

				published = e.find('vuln:published-datetime').string
				last_modified = e.find('vuln:last-modified-datetime').string
			
				score = e.find('cvss:score').string
				access_vector = e.find('cvss:access-vector').string
				access_complexity = e.find('cvss:access-complexity').string
				authentication = e.find('cvss:authentication').string
				confidentiality_impact = e.find('cvss:confidentiality-impact').string
				integrity_impact = e.find('cvss:integrity-impact').string
				availability_impact = e.find('cvss:availability-impact').string

				try:
					v = Vulnerability.objects.get(cve=cve)
					v.delete()
					a = Application.objects.filter(vulnerability__isnull=True)
					a.delete()
				except Vulnerability.DoesNotExist:
					pass
					
				v = Vulnerability(cve=cve,summary=summary,published=published,last_modified=last_modified,score=score,access_vector=access_vector,access_complexity=access_complexity,authentication=authentication,confidentiality_impact=confidentiality_impact,integrity_impact=integrity_impact,availability_impact=availability_impact)
				v.save()

				software = e.find_all('vuln:product')
				for product in software:
					try:
						a = Application.objects.get(cpe=product.string)
						a.vulnerability.add(v)
						a.save()
					except Application.DoesNotExist:
						a = Application(cpe=product.string)
						a.save()
						a.vulnerability.add(v)
						a.save()

				reference = e.find_all('vuln:references')
				for ref in reference:
					type =  ref['reference_type']
					source = ref.find('vuln:source').string
					address =  ref.find('vuln:reference')['href']
					text = ref.find('vuln:reference').string
					r = Reference(vulnerability=v,source=source,address=address,text=text,type=type)
					r.save()
