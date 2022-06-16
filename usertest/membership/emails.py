from django.core.mail import send_mail
import random
from .models import User

def generate_otp():
    otp = random.randint(1000,9999)
    return str(otp)


def send_otp_via_email(email):
    subject = 'Your account verifiction email'
    otp = generate_otp()
    massage = otp
    send_mail(subject,massage , 'test@test.com', [email])
    user_obj = User.objects.get(email = email)
    user_obj.otp = otp
    user_obj.save()
