from authenticator.models import EstiamUser
from authenticator.serializers import VerifyOTPSerializer
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.shortcuts import redirect
from django.shortcuts import render


def main(request):
    # if request.method == 'POST':
    #     otp = ''.join([
    #         request.GET.get(f'otp{i}', '') for i in range(1, 7)
    #     ])
    #     print(otp,"erer")
    #     serialiazer = VerifyOTPSerializer(data={'code_otp':otp})
    #     serialiazer.is_valid(raise_exception=True)
    #     user = EstiamUser.objects.get(email=serialiazer.validated_data['email'])
    #     print("fdfdfd")
    #     if user is not None:
    #         login(request, user)
    #         request.session['username'] = user.username
    #         request.session['user_id'] = user.id
    #         request.session.set_expiry(1000)  # Set session to expire in 5 minutes
    # return render(request=request, template_name="welcome.html", context={'username': user.username})
    return render(request=request, template_name="otp.html")


# @login_required
def welcome(request):
    username = request.session.get("username", "")
    return render(
        request=request, template_name="welcome.html", context={"username": username}
    )


def send_email(request):
    return render(request=request, template_name="email.html")
