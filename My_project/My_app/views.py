from django.shortcuts import render
from rest_framework import generics, status, views, permissions, mixins
from .serializers import RegisterSerializer, SetNewPasswordSerializer, ResetPasswordEmailRequestSerializer, \
    LoginSerializer, LogoutSerializer, ProductSerializer
from rest_framework.response import Response
from rest_framework.authentication import TokenAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, Products
from .utils import Util
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
# from django.contrib.auth.models import User
from django.http import Http404
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .renderers import UserRenderer
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
from django.shortcuts import redirect
from django.http import HttpResponsePermanentRedirect
import os
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.core.mail import EmailMessage, send_mail
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView


class CustomRedirect(HttpResponsePermanentRedirect):
    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']


class RegisterView(generics.GenericAPIView):
    """Class For Registering New Users"""

    serializer_class = RegisterSerializer

    # renderer_classes = (UserRenderer,)

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        # relativeLink = reverse('email-verify')
        absurl = current_site + "?token=" + str(token)
        email_body = 'Hi ' + user.username + \
                     ' Thank you for registering \n' + absurl
        email_from = settings.EMAIL_HOST_USER
        data = {'email_body': email_body, 'to_email': user.email,
                'email_subject': 'Registration Success', 'email_from': email_from}

        Util.send_email(data)
        return Response(user_data, status=status.HTTP_201_CREATED)


class LoginAPIView(generics.GenericAPIView):
    """Class for User Login"""

    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(generics.GenericAPIView):
    """Class for user Password change request via email"""

    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        email = request.data.get('email', '')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse(
                'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            redirect_url = request.data.get('redirect_url', '')
            to_email = [user.email, ]
            print(to_email)
            absurl = current_site + relativeLink
            email_body = 'Hi ' + user.username + \
                         ' Use this link below to reset your password \n' + absurl \
                         + "?redirect_url = " + redirect_url
            # email_from = settings.EMAIL_HOST_USER
            from_1 = 'taskproject69@gmail.com'
            email_subject = 'Reset Password'
            email_body = email_body
            to_email = to_email
            send_mail(email_subject, email_body, from_1, to_email)
            return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPI(generics.GenericAPIView):
    """Class to get the token and uidb64 for changing password"""

    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid request new one'})
            return Response({'success': True, 'message': 'credentials valid', 'uidb64': uidb64, 'token': token},
                            status=status.HTTP_200_OK)
        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user):
                return Response({'error': 'Token is not valid, please request a new one'},
                                status=status.HTTP_400_BAD_REQUEST)


class SetNewPasswordAPIView(generics.GenericAPIView):
    """Class for setting New Passsword"""

    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ProductsCrudAPI(generics.GenericAPIView, mixins.ListModelMixin,
                      mixins.CreateModelMixin):
    queryset = Products
    serializer_class = ProductSerializer
    lookup_field = 'user'

    def get_object(self, id_1):
        try:
            user = User.objects.get(username=id_1)
            return Products.objects.filter(user=user.id)[0]
            # return product
        except Exception:
            return Http404

    def get(self, request, id=None, *args, **kwargs):

        if id:
            products = self.get_object(id)
            print(products)
            serializer = ProductSerializer(products)
            return Response(serializer.data, status=status.HTTP_200_OK)
        # else:
        #     return Http404
        # return Response(status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, id=None):

        if id:
            products = self.get_object(id)
            serializer = ProductSerializer(products, data=request.data)
            print(serializer)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProductsAPI(generics.GenericAPIView):
    queryset = Products
    serializer_class = ProductSerializer

    def get(self, request):
        queryset = Products.objects.all()
        serializer = ProductSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AdminViewAPI(generics.GenericAPIView, mixins.ListModelMixin):
    queryset = Products.objects.all()
    serializer_class = ProductSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def get(self, request):
        id_a = request.user.pk
        if id_a:
            queryset = Products.objects.filter(user_id=id_a)
            print(queryset)
        else:
            queryset = Products.objects.all()
        serializer = self.serializer_class(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


