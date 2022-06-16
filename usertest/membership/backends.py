import jwt
from rest_framework import authentication ,exceptions
from .models import User
from django.conf import settings
from django.contrib.auth.backends import ModelBackend


class EmailBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            User().set_password(password)
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user

    def user_can_authenticate(self, user):
        is_registered = getattr(user, 'is_registered', False)
        return super(EmailBackend, self).user_can_authenticate(user) and is_registered

#we can use JWTAuthentication for costum user authentication
'''
class JWTAuthentication(authentication.BaseAuthentication) :
    def authenticate(self , request):
        auth_data = authentication.get_authorization_header(request)

        if not auth_data :
            return None

        prefix, token = auth_data.decode('utf-8').split(' ')

        try :
            payload =jwt.decode(token , settings.SECRET_KEY,algorithms="HS256") 
            user =User.objects.get(email=payload['email'] )
            return (user , token)
          
        except jwt.DecodeError as identifier:
            raise exceptions.AuthenticationFailed(
                'Your token is invalid,login')
        except jwt.ExpiredSignatureError as identifier:
            raise exceptions.AuthenticationFailed(
                'Your token is expired,login')
        
        return super().authenticate(request)    
'''