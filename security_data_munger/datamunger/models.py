from django.db import models

# Create your models here.

class Vulnerability(models.Model):
	cve = models.CharField(max_length=30,unique=True)
	summary = models.CharField(max_length=1000)
	published = models.DateTimeField()
	last_modified = models.DateTimeField()
	score = models.CharField(max_length=30)
	access_vector = models.CharField(max_length=30)
	access_complexity = models.CharField(max_length=30)
	authentication = models.CharField(max_length=30)
	confidentiality_impact = models.CharField(max_length=30)
	integrity_impact = models.CharField(max_length=30)
	availability_impact = models.CharField(max_length=30)
	def __unicode__(self):
		return self.cve

class Reference(models.Model):
	vulnerability = models.ForeignKey(Vulnerability)
	source = models.CharField(max_length=200)
	address = models.CharField(max_length=200)
	text = models.CharField(max_length=200)
	type = models.CharField(max_length=30)

class Application(models.Model):
	cpe = models.CharField(max_length=200,unique=True)
	vulnerability = models.ManyToManyField(Vulnerability)
	def __unicode__(self):
		return self.name
