import re

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password

User = get_user_model()


class RegisterForm(forms.Form):
    username = forms.CharField(max_length=24, min_length=3)
    email = forms.EmailField()
    organization = forms.CharField(max_length=120, required=False)
    password = forms.CharField(widget=forms.PasswordInput)
    password2 = forms.CharField(widget=forms.PasswordInput, label="Repeat password")

    def clean_username(self):
        name = self.cleaned_data["username"].strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{3,24}", name):
            raise forms.ValidationError("Use 3 to 24 letters, numbers, dots, dashes or underscores.")
        if User.objects.filter(username__iexact=name).exists():
            raise forms.ValidationError("That username is taken.")
        return name

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this email already exists.")
        return email

    def clean(self):
        data = super().clean()
        pw, pw2 = data.get("password"), data.get("password2")
        if pw and pw2 and pw != pw2:
            self.add_error("password2", "The two passwords do not match.")
        elif pw:
            candidate = User(username=data.get("username", ""), email=data.get("email", ""))
            try:
                validate_password(pw, candidate)
            except forms.ValidationError as exc:
                self.add_error("password", exc)
        return data
