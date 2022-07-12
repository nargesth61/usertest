from rest_framework import serializers
from . import google
import os
from rest_framework.exceptions import AuthenticationFailed
from .register import Social_register 
from django.conf import settings




class GoogleSerializer(serializers.Serializer):
    auth_token = serializers.CharField()
     

    def validate_auth_token(self, auth_token):
        user_data = google.Google.validate(auth_token)
        try :
           user_data['sub']
        except :
            raise serializers.ValidationError('The token is invalid or expired. Please login again.')
        
        if user_data['aud'] != settings.GOOGLE_CLIENT_ID:
             raise AuthenticationFailed('oops, who are you?')
        
        user_id = user_data['sub']
        email = user_data['email']
        provider = 'google'

        return Social_register(
            provider=provider, user_id=user_id, email=email)






