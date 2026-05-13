from django.contrib.auth.base_user import BaseUserManager, AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.db import models

# Create your models here.

class UserAccountManager(BaseUserManager):
    def create_user(self, email, name, phone, password=None, user_type=None):
        if not email:
            raise ValueError("Users must have an email address")

        if user_type not in [UserAccount.UserTypes.ADMIN, UserAccount.UserTypes.SUPER_ADMIN]:
            raise ValueError("User type must be admin or super_admin")

        email = self.normalize_email(email).lower()

        user = self.model(
            email=email,
            name=name,
            phone=phone,
            user_type=user_type,
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, phone, password=None):
        user = self.create_user(
            email=email,
            name=name,
            phone=phone,
            password=password,
            user_type=UserAccount.UserTypes.SUPER_ADMIN,
        )
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user


class UserAccount(AbstractBaseUser, PermissionsMixin):
    class UserTypes(models.TextChoices):
        ADMIN = "admin", "Admin"
        SUPER_ADMIN = "super_admin", "Super Admin"

    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=255)
    user_type = models.CharField(
        max_length=20,
        choices=UserTypes.choices,
        default=UserTypes.ADMIN
    )
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    added_on = models.DateTimeField(auto_now_add=True)

    # Password reset (token-based, no email service required)
    reset_token = models.CharField(max_length=128, blank=True, null=True)
    reset_token_expires = models.DateTimeField(blank=True, null=True)

    objects = UserAccountManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "phone"]

    def __str__(self):
        return f"{self.email} ({self.user_type})"


class Contribution(models.Model):
    """A verified M-Pesa contribution submitted by a user.

    `txn_code` is the Safaricom transaction code (e.g. UEDQD3VQX9) and is
    globally unique — the same code can never be submitted twice.
    """

    user = models.ForeignKey(
        UserAccount,
        on_delete=models.CASCADE,
        related_name="contributions",
    )
    txn_code = models.CharField(max_length=32, unique=True, db_index=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    paid_at = models.DateTimeField()
    raw_message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-paid_at", "-created_at"]

    def __str__(self):
        return f"{self.txn_code} - {self.amount} ({self.user.email})"
