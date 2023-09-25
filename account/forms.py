from django import forms

from .models import User


class UserForm(forms.ModelForm):
    email = forms.CharField(
        widget=forms.TextInput(attrs={"class": "form-control", "required": "required"})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={"class": "form-control", "required": "required"}
        )
    )

    class Meta:
        model = User
        fields = [
            "email",
            "password",
        ]
