import email
from tkinter.ttk import Style
from rest_framework import serializers
from .models import User
from django.db import transaction, IntegrityError
from .emails import generate_otp
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer 
import django.contrib.auth.password_validation as validators
from django.core import exceptions
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken ,TokenError
from django.utils import timezone


class RegisterSerializer(serializers.ModelSerializer):
    default_error_messages = {
        'already_registered': ('The user is already registered'),
        'cannot_create_user': ('Unable to create account')
    }
    
    class Meta:
        model = User
        fields = ['email']
    def validate_email(self, email):
        try:
            user = User.objects.get(email = email)
            self.user = user
            if user and user.is_registered:
                self.fail('already_registered')
        except User.DoesNotExist:
            self.user = None
        return email
    
    def create(self, validated_data):
        if self.user:
            return self.user
        try:
            with transaction.atomic():
                user = User.objects.create(email=validated_data['email'], otp=generate_otp(), is_active=False)
        except IntegrityError:
            self.fail('cannot_create_user')
        return user
    
class VerifySerializer(serializers.Serializer):
    email=serializers.EmailField()
    otp=serializers.CharField()


class PassSerializer(serializers.Serializer):
    
    password=serializers.CharField(write_only=True, style={'input_type': 'password'})
    password2=serializers.CharField(write_only=True ,style={'input_type': 'password'})     
    def validate_password(self, value):
        try:    
            validators.validate_password(password=value, user=self.instance)
        except exceptions.ValidationError as error:
            raise serializers.ValidationError(list(error.messages))
        return value
    def validate(self, data):
        # super =Adding new behavior for new serializer base classes.Modifying the behavior slightly for an existing class.
         if data['password'] != data['password2']:
            raise serializers.ValidationError(
                ("The two password fields didn't match."))
         return data



class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(style={'input_type': 'password'},write_only=True)
    class Meta:
        model = User
        fields = ['email', 'password']
 
    def get_token(self, user):
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

    def validate(self, attrs ):
        email = attrs.get('email', '')
        password = attrs.get('password', '')
        user =auth.authenticate(email=email, password=password)
        
        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')
        
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        token=self.get_token(user)
        print(token)
        return {'email': user.email}

class Changepassword(serializers.Serializer):
    model= User
    old_pass =serializers.CharField(required=True,style={'input_type': 'password'})
    new_pass =serializers.CharField(required=True,style={'input_type': 'password'})



class otppassword(serializers.Serializer):
    email = serializers.CharField()

class Resetpassword(serializers.Serializer):
    otp = serializers.CharField()
    password=serializers.CharField(write_only=True, style={'input_type': 'password'})
    def validate_password(self, data):
        try:    
            validators.validate_password(password=data, user=self.instance)
        except exceptions.ValidationError as error:
            raise serializers.ValidationError(list(error.messages))
        return data

class Logoutserializer(serializers.Serializer) :
    refresh = serializers.CharField()
    default_error_message = {
        'bad_token': ('Token is expired or invalid')
     }
  
    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):

        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')
