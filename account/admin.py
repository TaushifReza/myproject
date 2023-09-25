from django.contrib.auth.admin import UserAdmin
from django.contrib import admin

from .models import User, ServiceUse, Transition, UserProfile, UserActivity

# Register your models here.


class CustomUserAdmin(admin.ModelAdmin):
    list_display = ("email", "is_active")
    ordering = ("-date_joined",)
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()
    readonly_fields = ("password",)


class TransitionAdmin(admin.ModelAdmin):
    list_display = ("user", "amount", "transition_date")
    ordering = ("-transition_date",)
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()


class ServiceUseAdmin(admin.ModelAdmin):
    list_display = ("user", "number_of_hits", "last_hit")
    ordering = ("-last_hit",)
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()


class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "credit_balance", "has_subscribed")
    ordering = ("-user",)
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()


class UserActivityeAdmin(admin.ModelAdmin):
    list_display = ("user", "status", "created_at")
    ordering = ("-created_at",)
    filter_horizontal = ()
    list_filter = ()
    fieldsets = ()


admin.site.register(User, CustomUserAdmin)
admin.site.register(ServiceUse, ServiceUseAdmin)
admin.site.register(Transition, TransitionAdmin)
admin.site.register(UserProfile, UserProfileAdmin)
admin.site.register(UserActivity, UserActivityeAdmin)
