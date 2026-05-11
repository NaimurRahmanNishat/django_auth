from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.conf import settings
from .serializers import RegisterSerializer, UserSerializer
from rest_framework.response import Response
from rest_framework import status, permissions
from django.utils.decorators import method_decorator 
from django_ratelimit.decorators import ratelimit
from django.middleware.csrf import get_token


class RegisterView(APIView):

    def post(self, request):

        serializer = RegisterSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()

            return Response({
                'message': 'User registered successfully'
            })

        return Response(serializer.errors, status=400)




@method_decorator(ratelimit(key='ip', rate='5/m', method='POST', block=True), name='dispatch')
class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):

        get_token(request)
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response(
                {"error": "Email and password are required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        user = authenticate(request, email=email, password=password)

        if user is None or not user.is_active:
            return Response({"error": "Invalid credentials."}, status=401)

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        response_data = {
            'message': 'Login successful',
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'role': getattr(user, 'role', None),
                'image': request.build_absolute_uri(user.image.url) if user.image else None,
            }
        }

        response = Response(response_data, status=status.HTTP_200_OK)
        cookie_secure = not settings.DEBUG 

        response.set_cookie(
            key='access_token',
            value=access_token,
            httponly=True,       
            secure=cookie_secure,
            samesite='Lax',      
            max_age=900        
        )

        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            httponly=True,
            secure=cookie_secure,
            samesite='Strict',   
            max_age=86400 * 30    
        )

        return response




class ProfileView(APIView):

    permission_classes = [IsAuthenticated]

    def get(self, request):

        serializer = UserSerializer(request.user)

        return Response(serializer.data)





class RefreshTokenView(APIView):

    def post(self, request):

        refresh_token = request.COOKIES.get('refresh_token')

        if not refresh_token:
            return Response({
                'message': 'Refresh token not found'
            }, status=status.HTTP_401_UNAUTHORIZED)

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            new_refresh_token = str(refresh)

            response = Response({
                'message': 'Token refreshed'
            }, status=status.HTTP_200_OK)

            cookie_secure = not settings.DEBUG

            response.set_cookie(
                key='access_token',
                value=access_token,
                httponly=True,
                secure=cookie_secure,
                samesite='Lax',
                max_age=900   # 15 minutes
            )

            response.set_cookie(
                key='refresh_token',
                value=new_refresh_token,
                httponly=True,
                secure=cookie_secure,
                samesite='Strict',
                max_age=86400 * 30 # 30 days
            )

            return response

        except (TokenError, Exception):
            return Response({
                'message': 'Invalid refresh token'
            }, status=status.HTTP_401_UNAUTHORIZED)





class LogoutView(APIView):

    def post(self, request):

        response = Response({
            'message': 'Logout successful'
        }, status=status.HTTP_200_OK)

        cookie_secure = not settings.DEBUG

        # Access Token 
        response.delete_cookie(
            key='access_token',
            path='/',
            samesite='Lax'
        )

        # Refresh Token
        response.delete_cookie(
            key='refresh_token',
            path='/',
            samesite='Strict'
        )

        # CSRF Token 
        response.delete_cookie(
            key='csrftoken',
            path='/',
            samesite='Lax' 
        )

        return response

