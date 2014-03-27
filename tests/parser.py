from bs4 import BeautifulSoup

#soup = BeautifulSoup(open("nvdcve-2.0-2003.xml"), "xml")
soup = BeautifulSoup(open("temp.xml"))
#a = soup.entry['id']
#print a

entry = soup.find_all('entry')

for e in entry:
	cve = e.find('vuln:cve-id').string
	summary = e.find('vuln:summary').string
	software = e.find_all('vuln:vulnerable-software-list')
	for product in software:
		print product.string
