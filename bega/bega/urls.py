"""
URL configuration for bega project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
import scan.views
import authentication.views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', scan.views.home, name="scan-home"),
    path('scans/', scan.views.scan_list, name="scan-list"),
    path('scans/<int:id>/', scan.views.scan_detail, name="scan-detail"),
    path('scans/add/', scan.views.scan_create, name="scan-create"),
    path('scan/<int:id>/update', scan.views.scan_update, name="scan-update"),
    path('scan/<int:id>/delete', scan.views.scan_delete, name="scan-delete"),
    path('login/', authentication.views.login_page, name="login"),
    path('logout/', authentication.views.logout_user, name='logout'),
    path('signup/', authentication.views.signup_page, name='signup'),
    path('legal/', scan.views.legal, name="legal"),    
    path('scan/<int:id>/report_create', scan.views.report_create, name="report-create"),
    path('reports/', scan.views.report_list, name="report-list"),
    path('reports/<int:id>/', scan.views.report_detail, name="report-detail"),
    path('reports/<int:id>/delete', scan.views.report_delete, name="report-delete"),

    
]
