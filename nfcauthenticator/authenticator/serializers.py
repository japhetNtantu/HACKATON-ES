import re
import time

import jwt
from authenticator.models import EstiamUser
from authenticator.models import Material
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode as uid_decoder
from django.utils.translation import gettext_lazy as _
from jwt.exceptions import DecodeError
from jwt.exceptions import ExpiredSignatureError
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


UserModel = get_user_model()


class ObtainTokenSerializer(TokenObtainPairSerializer):
    username_field = UserModel.EMAIL_FIELD


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = EstiamUser
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
        model = EstiamUser
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


class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={"input_type": "password"}, write_only=True)

    class Meta:
        model = EstiamUser
        fields = [
            "email",
            "username",
            "password",
            "password2",
        ]
        read_only_fields = ["id", "password2"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.get("password2")
        if password != password2:
            raise serializers.ValidationError(
                "Password and Confirm Password doesn't match"
            )

        try:
            validate_password(password)
        except ValidationError as e:
            raise serializers.ValidationError(e)
        return attrs

    def create(self, validate_data):
        validate_data.pop("password2", None)
        return EstiamUser.objects.create_user(**validate_data)


class SendMailSerialiazer(serializers.Serializer):
    user_code = serializers.IntegerField()

    def validate(self, attrs):
        user_uuid = attrs.get("user_code")
        try:
            obj = EstiamUser.objects.get(user_code=user_uuid)
            self.email = obj.email
        except EstiamUser.DoesNotExist:
            raise serializers.ValidationError("User does not exists")
        return attrs

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation.pop("user_code", None)
        representation.update({"email": self.email})
        return representation


class VerifyOTPSerializer(serializers.Serializer):
    code_otp = serializers.CharField()

    def validate(self, attrs):
        otp_num = attrs.get("code_otp")
        if not EstiamUser.objects.filter(confirm_number=otp_num).exists():
            raise serializers.ValidationError("Unrecognize otp code or not valid")
        else:
            self.obj_user = EstiamUser.objects.filter(confirm_number=otp_num).first()
        return attrs

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        representation.pop("code_otp", None)
        representation.update(
            {"email": self.obj_user.email, "username": self.obj_user.username}
        )
        return representation


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ["email"]


class ResendActivationCode(SendPasswordResetEmailSerializer):
    def validate(self, attrs):
        email = attrs.get("email")
        try:
            EstiamUser.objects.get(email=email, is_confirmed=False)
        except EstiamUser.DoesNotExist:
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


class JWTSerializer(serializers.Serializer):
    jwt_token = serializers.CharField()

    def _validate_exp(self, payload: dict) -> None:
        try:
            exp = int(payload.get("exp"))
        except ValueError:
            raise DecodeError("Expiration Time claim (exp) must be an" " integer.")

        current_time = int(time.time())

        if current_time > exp:
            raise ExpiredSignatureError("Token has expired")

    def _validate_user(self, email: str) -> None:
        try:
            EstiamUser.objects.get(email=email)
        except EstiamUser.DoesNotExist as err:
            raise ValidationError(err)

    def validate(self, attrs):
        token = attrs.get("jwt_token")
        self.decode_data = jwt.decode(
            jwt=token, algorithms=["HS256"], options={"verify_signature": False}
        )
        if self.decode_data:
            self._validate_user(self.decode_data.get("email"))
            self._validate_exp(self.decode_data)
        return super().validate(attrs)

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        user_email = self.decode_data.get("email")
        representation.update(
            {"email": user_email, "username": self.decode_data.get("name")}
        )
        representation.pop("jwt_token", None)
        return representation
