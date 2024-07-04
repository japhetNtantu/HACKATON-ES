from authenticator import user_views
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include
from django.urls import path
from drf_spectacular.views import SpectacularAPIView
from drf_spectacular.views import SpectacularRedocView
from drf_spectacular.views import SpectacularSwaggerView

urlpatterns = [
    path("", user_views.main, name="dashboard"),
    path("welcome/", user_views.welcome, name="welcome-page"),
    path("confirm/", user_views.send_email, name="email"),
    path("admin/", admin.site.urls),
    path("api/auth/", include("authenticator.urls")),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "api/swagger/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="swagger",
    ),
    path(
        "api/redoc/",
        SpectacularRedocView.as_view(url_name="schema"),
        name="redoc",
    ),
]
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
