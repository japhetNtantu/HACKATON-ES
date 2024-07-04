import random

from authenticator.models import EstiamUser
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string


class MailManagement:
    @staticmethod
    def send_code_for_verification(email: str) -> None:
        subject: str = "[Code OTP] Verification de votre email"
        otp: int = random.randint(settings.MIN_VALUE, settings.MAX_VALUE)
        user: EstiamUser = EstiamUser.objects.get(email=email)
        message = render_to_string(
            template_name="verify_email.html",
            context={
                "user": user,
                "code": f"{settings.HOST_BACKEND}/?code={otp}",
                "email_for_reply": settings.EMAIL_FOR_REPLY,
            },
        )
        email_from = settings.DEFAULT_FROM_EMAIL
        send_mail(
            subject=subject,
            message=message,
            from_email=email_from,
            recipient_list=[email],
            fail_silently=False,
            html_message=message,
        )
        user.confirm_number = otp
        user.save()
