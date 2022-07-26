from django.contrib import admin
from django.urls import path ,include

from .views import Googlelogin

urlpatterns = [
    path('google/', Googlelogin.as_view()),
  
]