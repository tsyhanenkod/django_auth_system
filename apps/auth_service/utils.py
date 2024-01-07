import random 
from django.core.mail import EmailMessage
from .models import User, OneTimePassword
from backend import settings


def generateOtp():
    otp=""
    for i in range(6):
        otp += str(random.randint(1,9))
    return otp


def send_code_to_user(email):
    Subject="One time password for Email verification"
    otp_code=generateOtp()
    print(otp_code)
    user=User.objects.get(email=email)
    print(user)
    current_site="myAuth.com"
    email_body=f"""
        Hi {user.first_name},\n\n
        
        Your one time password for email verification is {otp_code}.\n\n
        
        Thanks,\n
        Study Pilot Team
    """
    from_email=settings.DEFAULT_FROM_EMAIL
    
    
    OneTimePassword.objects.create(user=user, code=otp_code)
    
    d_email=EmailMessage(subject=Subject, body=email_body, from_email=from_email, to=[email])
    d_email.send(fail_silently=True)
    
    
def send_normal_email(data):
    email=EmailMessage(
        subject=data['email_subject'], 
        body=data['email_body'], 
        from_email=settings.DEFAULT_FROM_EMAIL, 
        to=[data['to_email']]
    )
    email.send()