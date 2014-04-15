from django.conf.urls import patterns, include, url
from tastypie.api import Api
from datamunger.api import VulnerabilityResource, ApplicationResource, ReferenceResource
from django.contrib import admin

admin.autodiscover()

v1_api = Api(api_name='v1')
v1_api.register(VulnerabilityResource())
v1_api.register(ReferenceResource())
v1_api.register(ApplicationResource())

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'security_data_munger.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

    url(r'^admin/', include(admin.site.urls)),
    url(r'^api/', include(v1_api.urls)), 
)
