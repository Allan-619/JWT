from django.urls import path,include
from . import views
from .views import RegisterView, LogoutAPIView, SetNewPasswordAPIView, LoginAPIView, PasswordTokenCheckAPI, RequestPasswordResetEmail
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenObtainPairView
)


urlpatterns = [
    path('', RegisterView.as_view(), name="register"),
    path('login/', LoginAPIView.as_view(), name="login"),
    path('logout/', LogoutAPIView.as_view(), name="logout"),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('request-reset-email/', RequestPasswordResetEmail.as_view(),
         name="request-reset-email"),
    path('password-reset/<uidb64>/<token>/',
         PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(),
         name='password-reset-complete'),
    path('crud/<str:id>/',views.ProductsCrudAPI.as_view()),
    path('products/',views.ProductsAPI.as_view()),
    path('view/',views.AdminViewAPI.as_view()),
    path('token/',TokenObtainPairView.as_view(),name='token_obtain-pair'),
    path('token/refresh/',TokenRefreshView.as_view(),name='token_refresh'),
    path('auth/',include('rest_framework.urls'))

]
