from datetime import timedelta

from django.utils import timezone
from django.contrib.auth import authenticate, login
from django.conf import settings
from django.contrib.auth import get_user_model

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions

from rest_framework_simplejwt.tokens import RefreshToken

from user.tasks import celery_send_email

from user.models import LoginAttempt
from user.api.serializers import RegisterSerializer, LoginSerializer, OTPVerifySerializer
import logging
from utils import generate_otp, save_otp_to_redis, get_otp_from_redis, delete_otp_from_redis

logger = logging.getLogger("sanaap v1 :")

User = get_user_model()


class RegisterAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")

        if not email:
            return Response({"error": "ایمیل الزامی است."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)

            if user.is_active:
                logger.info(f"کاربر {email} قبلاً فعال شده.")
                return Response({"error": "این کاربر قبلاً ثبت‌نام و فعال شده است."}, status=400)

            # اگر کاربر غیرفعال هست → ارسال مجدد OTP
            otp = get_otp_from_redis(email)
            if not otp:
                otp = generate_otp()
                save_otp_to_redis(email, otp)
                logger.info(f"OTP جدید ساخته شد برای {email}")
            else:
                logger.info(f"ارسال مجدد OTP برای {email} (قبلاً در Redis ذخیره شده بود)")

            celery_send_email.delay(email=email, subject="کد تایید حساب", message=f"کد تایید حساب شما: {otp}")

            return Response({"message": "OTP مجدد ارسال شد. لطفاً ایمیل را چک کنید."}, status=200)

        except User.DoesNotExist:
            # ثبت‌نام جدید
            serializer = RegisterSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.save(is_active=False)
                otp = generate_otp()
                save_otp_to_redis(user.email, otp)
                logger.info(f"ثبت‌نام جدید و ارسال OTP برای {user.email}")

                celery_send_email.delay(email=email, subject="کد تایید حساب", message=f"کد تایید حساب شما: {otp}")

                return Response({'message': 'ثبت‌نام موفق. لطفاً کد OTP را بررسی کنید.'}, status=200)

            logger.warning(f"خطا در ثبت‌نام: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class OTPVerifyAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = OTPVerifySerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']

            saved_otp = get_otp_from_redis(email)
            if saved_otp and saved_otp == otp:
                try:
                    user = User.objects.get(email=email)
                    user.is_active = True
                    user.save()
                    delete_otp_from_redis(email)

                    logger.info(f"✅ OTP تایید شد برای {email}")
                    return Response({'message': 'حساب شما تایید شد.'})
                except User.DoesNotExist:
                    logger.warning(f"❌ تلاش برای تایید OTP اما کاربر {email} وجود ندارد")
                    return Response({'error': 'کاربر پیدا نشد'}, status=404)

            logger.warning(f"❌ OTP اشتباه وارد شده برای {email}")
            return Response({'error': 'کد OTP نادرست است'}, status=400)

        logger.warning(f"❌ خطا در اعتبارسنجی فرم OTP: {serializer.errors}")
        return Response(serializer.errors, status=400)


class LoginAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            ip = request.META.get('REMOTE_ADDR')
            device = request.META.get('HTTP_USER_AGENT', 'unknown')

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                logger.warning(f"❌ تلاش برای ورود با ایمیل ناشناخته: {email} از IP: {ip}")
                return Response({'error': 'کاربر یافت نشد'}, status=404)

            recent_failed = LoginAttempt.objects.filter(
                user=user,
                successful=False,
                timestamp__gte=timezone.now() - timedelta(minutes=15)
            )

            if recent_failed.count() >= 5:
                last = recent_failed.last()
                if timezone.now() < last.timestamp + timedelta(minutes=15):
                    logger.warning(f"🚫 حساب قفل شده برای {email} به دلیل تلاش‌های زیاد - IP: {ip}")
                    return Response({'error': 'حساب شما به مدت ۱۵ دقیقه قفل شده است'}, status=403)

            auth_user = authenticate(request, email=email, password=password)
            if auth_user:
                if not auth_user.is_active:
                    logger.warning(f"⚠️ ورود توسط کاربر تأیید نشده: {email}")
                    return Response({'error': 'حساب شما هنوز تأیید نشده است'}, status=403)

                login(request, auth_user)

                LoginAttempt.objects.create(
                    user=user,
                    ip_address=ip,
                    device_info=device,
                    successful=True
                )

                logger.info(f"✅ ورود موفق برای {email} از IP: {ip} با دستگاه: {device}")

                refresh = RefreshToken.for_user(auth_user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'message': 'ورود موفق'
                })

            login_attempt = LoginAttempt.objects.create(
                user=user,
                ip_address=ip,
                device_info=device,
                successful=False,
                failure_reason='رمز عبور اشتباه'
            )

            suspicious_failed_attempts = LoginAttempt.objects.filter(
                ip_address=ip,
                successful=False,
                timestamp__gte=timezone.now() - timedelta(hours=1)
            ).count()

            if suspicious_failed_attempts > 10:
                login_attempt.is_suspicious = True
                login_attempt.save()
                logger.warning(f"🚨 فعالیت مشکوک از IP: {ip} - تعداد تلاش‌های ناموفق: {suspicious_failed_attempts}")
                celery_send_email.delay(
                    email=email,
                    subject="🚨 هشدار: فعالیت مشکوک در حساب شما",
                    message=f"تعداد تلاش‌های ناموفق زیادی از IP: {ip} برای حساب شما ثبت شده است."
                )
                celery_send_email.delay(
                    email=settings.ADMINISTRATOR_EMAIL,
                    subject=f"🚨 هشدار: فعالیت مشکوک در حساب شما{email}",
                    message=f"تعداد تلاش‌های ناموفق زیادی از IP: {ip} برای حساب {email} ثبت شده است."
                )

            logger.warning(f"❌ ورود ناموفق برای {email} از IP: {ip} با دستگاه: {device}")

            return Response({'error': 'اطلاعات ورود نادرست است'}, status=401)

        logger.warning(f"❌ فرم نامعتبر ورود: {serializer.errors}")
        return Response(serializer.errors, status=400)
