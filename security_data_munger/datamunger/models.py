from django.db import models

# Create your models here.

class Vulnerability(models.Model):
	cve = models.CharField(max_length=30)
	summary = models.CharField(max_length=1000)
	def __unicode__(self):
		return self.cve	

class Application(models.Model):
	name = models.CharField(max_length=200)
	vulnerability = models.ForeignKey(Vulnerability)
	def __unicode__(self):
		return self.name
