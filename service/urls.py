from django.conf import settings
from django.urls import path
from django.views.generic import RedirectView
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from members import views

urlpatterns = [
    path('', RedirectView.as_view(url='/member/account/', permanent=False)),
    path('member/register/', views.register),
    path('member/sign-in/', views.sign_in),
    path('member/recovery/', views.recovery),
    path('member/confirm/', views.confirm),
    path('member/account/', views.account),
    path('member/logout/', views.sign_out),
    path('member/configuration/', views.configuration),
    path('member/restore/<int:number>/', views.restore),
    path('member/devices/', views.devices),
    path('member/security/', views.security),
    path('member/export/', views.export),
    path('member/delete/', views.delete_account),
    path('member/approve/', views.approve),
    path('api/member/authorize/', views.authorize),
    path('api/member/exchange/', views.exchange),
    path('api/member/account/', views.native_account),
    path('api/member/feed/', views.feed),
    path('api/member/app-routing/', views.app_routing),
    path('api/member/revoke/', views.revoke),
]
if settings.DEV:
    from django.views.static import serve
    urlpatterns += [path('member-static/<path:path>', serve, {'document_root': settings.BASE_DIR / 'static'}), path('style.css', serve, {'document_root': settings.BASE_DIR.parent, 'path': 'style.css'}), path('assets/<path:path>', serve, {'document_root': settings.BASE_DIR.parent / 'assets'})]
