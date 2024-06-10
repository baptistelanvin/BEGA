from django.contrib import admin
from scan.models import Scan, Report
from authentication.models import User

class ScanAdmin(admin.ModelAdmin):
    list_display =('domain_name','tapirus','goat','owl','kangaroo','badger','limit','dkim')

class UserAdmin(admin.ModelAdmin):
    list_display = ('last_login','is_superuser','username','email','role')

class ReportAdmin(admin.ModelAdmin):
    list_display = ('name','date','scan.user')

admin.site.register(Scan)
admin.site.register(Report)
admin.site.register(User)
