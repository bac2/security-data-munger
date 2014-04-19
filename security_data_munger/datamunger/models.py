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

class Cpe(models.Model):
	cpe = models.CharField(max_length=200,unique=True)
	part = models.CharField(max_length=200)
	vendor = models.CharField(max_length=200)
	product = models.CharField(max_length=200)
	version = models.CharField(max_length=200)
	update = models.CharField(max_length=200)
	edition = models.CharField(max_length=200)
	language = models.CharField(max_length=200)
	sw_edition = models.CharField(max_length=200)
	target_sw = models.CharField(max_length=200)
	target_hw = models.CharField(max_length=200)
	other = models.CharField(max_length=200)
	title = models.CharField(max_length=200)

class Application(models.Model):
	cpe = models.ForeignKey(Cpe)
	vulnerability = models.ManyToManyField(Vulnerability)
	def __unicode__(self):
		return self.name
