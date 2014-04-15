from tastypie.resources import ModelResource
from tastypie import fields
from datamunger.models import Vulnerability, Application, Reference

class VulnerabilityResource(ModelResource):
	class Meta:
		queryset = Vulnerability.objects.all()
		allowed_methods = ['get']

class ReferenceResource(ModelResource):
	vulnerability = fields.ForeignKey(VulnerabilityResource, 'vulnerability')
	class Meta:
		queryset = Reference.objects.all()
		allowed_methods = ['get']

class ApplicationResource(ModelResource):
	vulnerability = fields.ToManyField(VulnerabilityResource, 'vulnerability')
	class Meta:
		queryset = Application.objects.all()
		allowed_methods = ['get']

