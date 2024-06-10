from django import forms

class LoginForm(forms.Form):
    email = forms.CharField(max_length=63, label='Email', widget=forms.TextInput(attrs={'class': 'form-input mt-1 block w-full'}))
    password = forms.CharField(max_length=63, label='Mot de passe', widget=forms.PasswordInput(attrs={'class': 'form-input mt-1 block w-full'}))


from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm

class SignupForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = get_user_model()
        fields = ('username', 'email', 'role')
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-input mt-1 block w-full'}),
            'email': forms.EmailInput(attrs={'class': 'form-input mt-1 block w-full'}),
            'role': forms.Select(attrs={'class': 'form-select mt-1 block w-full'}),
            'password1': forms.PasswordInput(attrs={'class': 'form-input mt-1 block w-full'}),
            'password2': forms.PasswordInput(attrs={'class': 'form-input mt-1 block w-full'}),
        }