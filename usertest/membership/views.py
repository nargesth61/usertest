from rest_framework.views import APIView
from rest_framework.response import Response
from .serializer import *
from rest_framework import status ,permissions
from .emails import send_otp_via_email
from .models import User
from django.utils import timezone
import datetime
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.shortcuts import get_object_or_404
from django.shortcuts import redirect
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView 
from django.contrib import auth
import jwt


class RegisterAPI(APIView):
    permission_classes = (
        permissions.AllowAny,
    )
    serializer_class = RegisterSerializer
    def post(self, request):
            serializer = RegisterSerializer(data = request.data)
            if serializer.is_valid(raise_exception=True):
               serializer.save()
               send_otp_via_email(serializer.data['email'])
               return Response(serializer.data, status=status.HTTP_201_CREATED)
            
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
class VerifyAPI(APIView):
    permission_classes = (
        permissions.AllowAny,
    )
    serializer_class = VerifySerializer
    def post(self, request):
        serializer = VerifySerializer(data = request.data)
        if serializer.is_valid():
            email = serializer.data['email']
            otp = serializer.data['otp']
            user = User.objects.filter(email = email)
            if not user.exists():
                  return Response('invalid email', status=status.HTTP_400_BAD_REQUEST)        
            #user[0] = Because users emails are unique, the first user with this email
            if user[0].otp != otp :
                  return Response('wrong otp', status=status.HTTP_400_BAD_REQUEST)                     
            user = user.first()
            user.is_verified = True
            user.is_active = True
            user.save(update_fields=['is_verified', 'is_active'])
            x=user.id
            return redirect('http://127.0.0.1:8000/api/password/%s/'% x)
             
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)        

class PassViewAPI(APIView):
    permission_classes = (
        permissions.AllowAny,
    )
    serializer_class = PassSerializer
    def get_queryset(self):
        user = User.objects.all()
        return user
    def get_object(self, id):
        return get_object_or_404(self.get_queryset(), id=id)
   
    def get(self, request,pk=None,):     
        id = pk
        if id:
            serializer = PassSerializer(self.get_object(id))
        else:
            serializer = PassSerializer(self.get_queryset(), many=True)
        
        return Response(serializer.data)
    
    def post(self, request,pk=None,*args, **kwargs):
        
        user = self.get_object(pk)
        serializer =PassSerializer(data=request.data)
       # print(user.email)
        serializer.is_valid(raise_exception=True)
        user.set_password(serializer.validated_data['password'])
        user.is_registered = True
        user.save(update_fields=['password', 'is_registered'])
        return Response('Your authentication process is complete',status=status.HTTP_204_NO_CONTENT)

class LoginView(APIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = LoginSerializer
    def post(self,request):
        serializers =self.serializer_class(data=request.data)
        serializers.is_valid(raise_exception=True)
        return Response(serializers.data,status=status.HTTP_200_OK)
  
class ChangepassworView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = Changepassword
    model = User
    def get_object(self, queryset=None):
        user = self.request.user
        return user
    
    def post(self, request, *args, **kwargs):
        user = self.get_object()
        serializer =self.serializer_class(data=request.data)

        if serializer.is_valid():
            old_pass = serializer.data['old_pass']
            new_pass = serializer.data['new_pass']
            if not user.check_password(old_pass) :
                return Response ({'massage:':'Wrong password.'}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(new_pass)
            user.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': user.email
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class OtptpasswordView(APIView):
    permission_classes =(permissions.AllowAny,)
    serializer_class =otppassword
    
    def post(self,request):
        serializer =self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.data['email']
            user = User.objects.filter(email =email)
            
            if not user.exists(): 
                 return Response({'wrong:': 'There are no users with this email '}, status=status.HTTP_404_NOT_FOUND)
            if user[0].is_registered == False:
                 return Response({'wrong:': 'user not registered'}, status=status.HTTP_404_NOT_FOUND)
            user = user.first()
            x=user.id
            send_otp_via_email(email)
            return redirect('http://127.0.0.1:8000/api/resetpassword/%s/'% x)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResetpasswordView(APIView):
    permission_classes =(permissions.AllowAny,)
    serializer_class =Resetpassword
    model = User
    def get_queryset(self):
        user = User.objects.all()
        return user
    def get_object(self, id):
        return get_object_or_404(self.get_queryset(), id=id)
   
    def get(self, request,pk=None,):     
        id = pk
        if id:
            serializer = Resetpassword(self.get_object(id))
        else:
            serializer = Resetpassword(self.get_queryset(), many=True)
        
        return Response(serializer.data)
    def post(self, request,pk=None,*args, **kwargs):
        user = self.get_object(pk)
        serializer =Resetpassword(data=request.data)
        if serializer.is_valid(raise_exception=True):
           otp =serializer.data['otp']
           password=serializer.validated_data['password']
           if user.otp != otp :
             return Response('wrong otp', status=status.HTTP_400_BAD_REQUEST)
           user.set_password(password)
           user.save(update_fields=['password'])
           return Response({'change password':'ok'},status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
 
    '''
    def post(self,request) :
        data = request.data
        email = data.get('email', '')
        password = data.get('password', '')
       
        user =auth.authenticate(email=email, password=password)
        print('yess',user)
        if user :
           
           auth_token = jwt.encode(
                {'email':user.email}, settings.SECRET_KEY ,algorithm="HS256" )
            
           serializer =  RegisterSerializer(user)
           user.last_login = timezone.now()
           user.save(update_fields=['last_login'])

           data = {'user': serializer.data, 'token': auth_token}
           return Response(data, status=status.HTTP_200_OK)

            # SEND RES
        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

    '''

class LogoutView(APIView):
    serializer_class = Logoutserializer
    permission_classes = (permissions.IsAuthenticated,)
     
    def post (self,request):
        serializers =self.serializer_class(data=request.data)
        serializers.is_valid(raise_exception=True)
        serializers.save()

        return Response(status=status.HTTP_204_NO_CONTENT )

