from django.core.management.base import BaseCommand, CommandError
from datamunger.models import Vulnerability, Application, Reference, Cpe
import urllib2
import gzip
import sys
from StringIO import StringIO
from bs4 import BeautifulSoup
from optparse import make_option

class Command(BaseCommand):

	urls = [
		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-modified.xml'
	]

	urls_initialise = [
		'http://users.ecs.soton.ac.uk/temt1g10/temp.xml',
#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2002.xml',	
#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2003.xml',	
#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2004.xml',	
#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2005.xml',	
#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2006.xml',	
#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2007.xml',	
#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2008.xml',	
#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2009.xml',	
#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2010.xml',	
#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2011.xml',	
#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2012.xml',	
#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2013.xml',	
#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2014.xml'
	]

	option_list = BaseCommand.option_list + (
		make_option('--initialise',
			action='store_true',
			dest='initialise',
			default=False,
			help='Pulls entire history'),
		make_option('--cpe',
			action='store_true',
			dest='cpe',
			default=False,
			help='Updates cpe data'),
		)

	def handle(self, *args, **options):


		urls = [
			'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-modified.xml'
		]

		urls_initialise = [
			'http://users.ecs.soton.ac.uk/temt1g10/temp.xml',
	#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2002.xml',	
	#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2003.xml',	
	#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2004.xml',	
	#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2005.xml',	
	#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2006.xml',	
	#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2007.xml',	
	#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2008.xml',	
	#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2009.xml',	
	#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2010.xml',	
	#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2011.xml',	
	#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2012.xml',	
	#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2013.xml',	
	#		'http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2014.xml'
		]

		if options['cpe']:
			print 'Saving CPE 2.3 data'
			self.cpe('http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz')
			print 'Saving CPE 2.2 data'
			self.cpe('http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.2.xml.gz')
		if options['initialise']:
			print 'Saving CVE data'
			self.cve(urls_initialise)
		else:
			print 'Saving CVE data'
			self.cve(urls)

	def cpe(self, url):
		cpe_dictionary = urllib2.urlopen(url)
		data = cpe_dictionary.read()
		data = StringIO(data)
		gzipper = gzip.GzipFile(fileobj=data)
		xml = gzipper.read()
		cpe_soup = BeautifulSoup(xml)

		cpe_list = cpe_soup.find_all('cpe-item')
		count = 0
		j = len(cpe_list)
		for item in cpe_list:
			sys.stdout.write("\r%d of %d" % (count, j))
			sys.stdout.flush()
			count += 1
			short_cpe = item['name']
			short_cpe = short_cpe.replace('~','*:')
			array = short_cpe.split(':')
			while len(array) < 12:
				array.append('*')
			title = item.find('title', { 'xml:lang' : 'en-US' }).string

			obj, created = Cpe.objects.get_or_create(cpe=item['name'],part=array[1],vendor=array[2],product=array[3],version=array[4],update=array[5],edition=array[6],language=array[7],sw_edition=array[8],target_sw=array[9],target_hw=array[10],other=array[11],title=title)

	def cve(self, urls):
	
		for url in urls:
			print 'Checking ' + url
			page = urllib2.urlopen(url)
			soup = BeautifulSoup(page.read())
			entry = soup.find_all('entry')
			
			count = 0
			j = len(entry)
			for e in entry:
				sys.stdout.write("\r%d of %d" % (count, j))
				sys.stdout.flush()
				count += 1

				cve = e.find('vuln:cve-id').string
				summary = e.find('vuln:summary').string

				published = e.find('vuln:published-datetime').string
				last_modified = e.find('vuln:last-modified-datetime').string
		
				try:	
					score = e.find('cvss:score').string
					access_vector = e.find('cvss:access-vector').string
					access_complexity = e.find('cvss:access-complexity').string
					authentication = e.find('cvss:authentication').string
					confidentiality_impact = e.find('cvss:confidentiality-impact').string
					integrity_impact = e.find('cvss:integrity-impact').string
					availability_impact = e.find('cvss:availability-impact').string
				except AttributeError:
					score = ""
					access_vector = ""
					access_complexity = ""
					authentication = ""
					confidentiality_impact = ""
					integrity_impact = ""
					availability_impact = ""

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
					short_cpe = product.string
					short_cpe = short_cpe.replace('~','*:')
					array = short_cpe.split(':')
					while len(array) < 12:
						array.append('*')

					query = {}
					options = {1:'part',2:'vendor',3:'product',4:'version',5:'update',6:'edition',7:'language',8:'sw_edition',9:'target_sw',10:'target_hw',11:'other'}

					for i in range(1, 11):
						if array[i] != '*':
							query[options[i]] = array[i]
					
					cpe = Cpe.objects.filter(**query)

					for c in cpe:
						try:
							a = Application.objects.get(cpe=c)
							a.vulnerability.add(v)
							a.save()
						except Application.DoesNotExist:
							a = Application(cpe=c)
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

