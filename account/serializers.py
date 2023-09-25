from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from .models import User


class UserSerializer(serializers.ModelSerializer):
    """Serializes a user profile object"""

    class Meta:
        model = User
        fields = (
            "email",
            "password",
        )
        extra_kwargs = {
            "password": {
                "write_only": True,
                "style": {"input_type": "password"},
            }
        }

    def create(self, validated_data):
        """Create and return a new user"""
        user = User.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
        )

        return user

    def update(self, instance, validated_data):
        """Handle updating user account"""
        if "password" in validated_data:
            password = validated_data.pop("password")
            instance.set_password(password)

        return super().update(instance, validated_data)


class LoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()


class ChangePassword(serializers.Serializer):
    email = serializers.CharField()
    current_password = serializers.CharField()
    new_password = serializers.CharField()

    def validate(self, data):
        current_password = data.get("current_password")
        new_password = data.get("new_password")

        try:
            user = User.objects.get(email=data.get("email"))
        except User.DoesNotExist:
            raise ValidationError("Invalid email address!")

        if current_password == new_password:
            raise ValidationError(
                "New password must be different from the current password."
            )

        return data


class ForgotPassword(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, data):
        try:
            user = User.objects.get(email=data.get("email"))
        except User.DoesNotExist:
            raise ValidationError("User with this email does not exist.")

        return data


class ForgotPasswordOtpValidate(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.IntegerField()
    new_password = serializers.CharField()
