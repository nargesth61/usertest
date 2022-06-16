from django.contrib import admin
from django.urls import path ,include
from membership.views import *
from . import views
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenVerifyView,
)

urlpatterns = [
    path('register/', views.RegisterAPI.as_view(), name='auth-register'),
    path('verify/', views.VerifyAPI.as_view(), name='auth-verify'),
    path('password/<int:pk>/', views.PassViewAPI.as_view(), name='auth-password'),
    path('login', views.LoginView.as_view(),name='login'),
    path('change-password', views.ChangepassworView.as_view(),name='change-password'),
    path('reset_pass',views.OtptpasswordView.as_view(),name='resetpass'),
    path('resetpassword/<int:pk>/',views.ResetpasswordView.as_view(),name='resetpassword'),
    path('logout',views.LogoutView.as_view(),name='Logout'),
   
    path('token/refresh/', TokenRefreshView.as_view(), name='auth-token-refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='auth-token-verify'),

]
