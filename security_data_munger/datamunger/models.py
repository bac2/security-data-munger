from django.db import models

# Create your models here.

class Vulnerability(models.Model):
	cve = models.CharField(max_length=30,unique=True)
	summary = models.CharField(max_length=1000)
	def __unicode__(self):
		return self.cve	

class Application(models.Model):
	cpe = models.CharField(max_length=200,unique=True)
	vulnerability = models.ManyToManyField(Vulnerability)
	def __unicode__(self):
		return self.name
