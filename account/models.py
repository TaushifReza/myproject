from datetime import timezone
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db.models.signals import post_save
from django.dispatch import receiver


# Create your models here.


class UserManager(BaseUserManager):
    def create_user(self, email, password=None):
        if not email:
            raise ValueError("Email is required!!!")

        if not email:
            raise ValueError("Username is required!!!")

        user = self.model(
            email=self.normalize_email(email),
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None):
        user = self.create_user(
            email=self.normalize_email(email),
            password=password,
        )
        user.is_admin = True
        user.is_staff = True
        user.is_active = True
        user.is_superadmin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    email = models.EmailField(max_length=50, unique=True)

    # required field
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now_add=True)
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date = models.DateTimeField(auto_now_add=True)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_superadmin = models.BooleanField(default=False)

    USERNAME_FIELD = "email"

    objects = UserManager()

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return True


class UserProfile(models.Model):
    BASIC = 1
    PRO = 2
    SUBSCRIPTION = {
        (BASIC, "Basic"),
        (PRO, "Pro"),
    }
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    credit_balance = models.DecimalField(max_digits=10, decimal_places=2, default=5.00)
    has_subscribed = models.PositiveSmallIntegerField(
        choices=SUBSCRIPTION, blank=True, default=BASIC
    )

    # def __str__(self):
    #     return self.user


class ServiceUse(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    number_of_hits = models.IntegerField(default=0)
    last_hit = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.user} {self.number_of_hits}"


class Transition(models.Model):
    FREE_TRIAL = 1
    LOAD = 2
    USE = 3
    TRANSITION_TYPE = (
        (FREE_TRIAL, "Free Trial"),
        (LOAD, "Load"),
        (USE, "Use"),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=3)
    transition_method = models.CharField(max_length=30, null=True, blank=True)
    transition_date = models.DateTimeField(auto_now_add=True)
    transition_type = models.PositiveSmallIntegerField(choices=TRANSITION_TYPE)

    # exipire_date = models.DateTimeField(auto_now=False, auto_now_add=False)

    def __str__(self):
        return f"{self.amount} {self.transition_date}"


class UserActivity(models.Model):
    CREDIT_GAIN = 1
    CREDIT_USE = 2
    CREDIT_EXPIRE = 3
    PAYMENT = 4
    STATUS_CHOOICE = {
        (CREDIT_GAIN, "Credit gain"),
        (CREDIT_USE, "Credit use"),
        (CREDIT_EXPIRE, "Credit expire"),
        (PAYMENT, "Payment"),
    }
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.PositiveSmallIntegerField(choices=STATUS_CHOOICE)
    created_at = models.DateTimeField(auto_now_add=True)


@receiver(post_save, sender=User)
def post_save_create_user_profile_service_use(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
        ServiceUse.objects.create(user=instance)
        UserActivity.objects.create(user=instance, status=1)


# @receiver(post_save, sender=User)
# def post_save_make_transition_receiver(sender, instance, created, **kwargs):
#     if created:
#         Transition.objects.create(user=instance, amount=5, transition_type=1)

#         # Update the user's balance
#         instance.balance = 5
#         instance.save()

#         ServiceUse.objects.create(user=instance)
