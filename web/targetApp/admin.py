from django.contrib import admin

from .models import *

admin.site.register(Domain)
admin.site.register(Organization)
admin.site.register(AssociatedDomain)
admin.site.register(RelatedTLD)
admin.site.register(NameServers)
admin.site.register(DomainRegistrar)
admin.site.register(DomainRegisterName)
admin.site.register(DomainRegisterOrganization)
admin.site.register(DomainAddress)
admin.site.register(DomainCity)
admin.site.register(DomainState)
admin.site.register(DomainZipCode)
admin.site.register(DomainCountry)
admin.site.register(DomainEmail)
admin.site.register(DomainPhone)
admin.site.register(DomainFax)
admin.site.register(DomainWhoisStatus)
admin.site.register(DomainRegistrarID)
admin.site.register(DomainInfo)
