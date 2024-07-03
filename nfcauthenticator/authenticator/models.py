from django.contrib.auth.models import AbstractUser
from django.contrib.auth.validators import ASCIIUsernameValidator
from django.db import models
from django.utils.translation import gettext_lazy as _


class DeviceTypeChoiceModel(models.TextChoices):
    COMPUTER = ("Computer", "computer")
    SERVER = ("Server", "server")


class Roles(models.TextChoices):
    EMPLOYEE = "employee", "Employee"


class EstiamUserModel(AbstractUser):
    username = models.CharField(
        _("username"),
        max_length=150,
        validators=[ASCIIUsernameValidator()],
        help_text=_(
            "Required. 150 characters or fewer. Lowercase a-z "
            "and uppercase A-Z letters, numbers"
        ),
        null=True,
    )
    email = models.EmailField(_("email"), unique=True)
    confirm_number = models.CharField(_("confirm number"), max_length=1000, null=True)
    is_confirmed = models.BooleanField(_("is confirmed"), default=False)
    roles = models.CharField(
        max_length=50,
        choices=Roles.choices,
        default=Roles.EMPLOYEE,
        verbose_name=_("role"),
    )
    created_by = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        related_name="created_by_user",
        null=True,
        blank=True,
        verbose_name=_("created by"),
    )

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=[
                    "confirm_number",
                ],
                name="confirm_number_unique",
            ),
        ]
        verbose_name = "User"

    def __str__(self):
        return (
            self.email + " (" + ("not " if not self.is_confirmed else "") + "confirmed)"
        )


class EstiamUser(EstiamUserModel):
    class Meta(EstiamUserModel.Meta):
        verbose_name = _("User")
        verbose_name_plural = _("User management")


class Material(models.Model):
    material_id = models.UUIDField(unique=True, auto_created=True, primary_key=True)
    user = models.ForeignKey(
        EstiamUser,
        on_delete=models.CASCADE,
        related_name="user_material",
        verbose_name=_("user"),
    )
    device_type = models.CharField(
        default=DeviceTypeChoiceModel.COMPUTER,
        choices=DeviceTypeChoiceModel.choices,
        max_length=140,
    )
    ip_adress = models.CharField(default="", null=True, max_length=120)
