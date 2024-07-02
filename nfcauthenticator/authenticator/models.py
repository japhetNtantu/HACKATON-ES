from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.validators import ASCIIUsernameValidator
from django.utils.translation import gettext_lazy as _

class DeviceTypeChoiceModel(models.TextChoices):
    COMPUTER = ("Computer", "computer")
    SERVER = ("Server", "server")

class EstiamUser(AbstractUser):
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


class Material(models.Model):
    material_id = models.UUIDField(unique=True, auto_created=True, primary_key=True)
    user = models.ForeignKey(EstiamUser)
    device_type = models.CharField(default=DeviceTypeChoiceModel.COMPUTER, choices=DeviceTypeChoiceModel.choices)
    ip_adress = models.IPAddressField(default=True, null=True)

