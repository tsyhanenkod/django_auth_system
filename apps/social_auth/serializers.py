from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from .utils import Google, register_social_user
from django.conf import settings


class GoogleSignInSerializer(serializers.Serializer):
    access_token=serializers.CharField(min_length=6)
    
    def validate_access_token(self, access_token):
        google_user_data=Google.validate(access_token)
        try:
            user_id=google_user_data['sub']
        except:
            raise serializers.ValidationError('The access token is either invalid or expired')
    
        if google_user_data['aud'] != settings.GOOGLE_CLIENT_ID:
            raise AuthenticationFailed('Could not verify user')
        email=google_user_data['email']
        first_name=google_user_data['given_name']
        last_name=google_user_data['family_name']
        provider='google'
        
        return register_social_user(provider, email, first_name, last_name)