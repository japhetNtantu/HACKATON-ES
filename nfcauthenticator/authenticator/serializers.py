import re

from authenticator.models import EkilaUser
from authenticator.models import Material
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode as uid_decoder
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import ValidationError


UserModel = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = EkilaUser
        fields = [
            "username",
            "first_name",
            "last_name",
            "email",
            "is_confirmed",
            "roles",
            "confirm_number",
        ]


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = EkilaUser
        fields = ["id", "email", "username", "first_name", "last_name", "roles"]
        read_only_fields = ["id", "email"]


class UserChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )
    new_password = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )
    confirm_password = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )

    class Meta:
        fields = ["password", "password2"]

    def validate(self, attrs):
        old_password = attrs.get("old_password")
        password = attrs.get("new_password")
        password2 = attrs.get("confirm_password")

        user = self.context.get("user")
        if not user.check_password(old_password):
            raise serializers.ValidationError("Old Password is not Correct")

        if password != password2:
            raise serializers.ValidationError(
                "New Password and Confirm Password doesn't match"
            )
        user.set_password(password)
        user.save()
        return attrs


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ["email"]


class ResendActivationCode(SendPasswordResetEmailSerializer):
    def validate(self, attrs):
        email = attrs.get("email")
        try:
            user = EkilaUser.objects.get(email=email, is_confirmed=False)
        except EkilaUser.DoesNotExist:
            raise serializers.ValidationError(
                "User does not exists or is already confirmed"
            )
        return attrs


class VerificationEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()
    confirm_number = serializers.CharField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)
    uid = serializers.CharField()
    token = serializers.CharField()

    set_password_form_class = SetPasswordForm

    def validate(self, attrs):
        self._errors = {}

        try:
            uid = force_str(uid_decoder(attrs["uid"]))
            self.user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            raise ValidationError({"uid": ["Invalid value"]})

        self.set_password_form = self.set_password_form_class(
            user=self.user, data=attrs
        )
        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)
        if not default_token_generator.check_token(self.user, attrs["token"]):
            raise ValidationError({"token": ["Invalid value"]})

        return attrs

    def save(self):
        return self.set_password_form.save()


class MaterialSerializer(serializers.ModelSerializer):
    class Meta:
        model = Material
        fields = ["device_type", "ip_adress"]
        exclude = ["user"]

    def validate(self, attrs):
        regex = r"\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b"
        if re.match(regex, attrs["ip_adress"]) is None:
            raise ValidationError("IP adress malformomed, check format")
        return super().validate(attrs)
