from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.db import models
from django.utils import timezone
from django.conf import settings


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("ایمیل باید وارد شود.")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    blocked_until = models.DateTimeField(null=True, blank=True)

    date_joined = models.DateTimeField(default=timezone.now)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

    def is_blocked(self):
        return self.blocked_until and timezone.now() < self.blocked_until



class LoginAttempt(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE,related_name='login_attempts')
    ip_address = models.GenericIPAddressField()
    device_info = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    successful = models.BooleanField(default=False)
    failure_reason = models.CharField(max_length=255, blank=True, null=True)
    is_suspicious = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']

        indexes = [
            models.Index(fields=['successful', 'timestamp', 'ip_address']),
        ]

    def __str__(self):
        status = "✅ موفق" if self.successful else "❌ ناموفق"
        suspicious_status = "⚠️ مشکوک" if self.is_suspicious else ""
        return f"{self.user.email} - {status} {suspicious_status} @ {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
