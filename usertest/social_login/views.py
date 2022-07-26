from rest_framework import status ,permissions
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from .serializer import GoogleSocialAuthSerializer


class Googlelogin(GenericAPIView):
    permission_classes = (
        permissions.AllowAny,
    )
    
    serializer_class = GoogleSocialAuthSerializer
    
    def post(self, request) :
        serializers = self.serializer_class(data=request.data)
        serializers.is_valid(raise_exception=True)
        data=((serializers.validated_data)['auth_token'])
        return Response(data , status=status.HTTP_200_OK)

