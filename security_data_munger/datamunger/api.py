from tastypie.resources import ModelResource
from tastypie import fields
from datamunger.models import Vulnerability, Application, Reference, Cpe

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
	cpe = fields.ForeignKey(CpeResource, 'cpe')
	class Meta:
		queryset = Application.objects.all()
		allowed_methods = ['get']

class CpeResource(ModelResource):
	class Meta:
		queryset = Cpe.objects.all()
		allowed_methods = ['get']

