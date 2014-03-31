from tastypie.resources import ModelResource
from tastypie import fields
from datamunger.models import Vulnerability, Application

class VulnerabilityResource(ModelResource):
	class Meta:
		queryset = Vulnerability.objects.all()
		allowed_methods = ['get']

class ApplicationResource(ModelResource):
	vulnerability = fields.ForeignKey(VulnerabilityResource, 'vulnerability')
	class Meta:
		queryset = Application.objects.all()
		allowed_methods = ['get']

