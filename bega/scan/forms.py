from django import forms

from scan.models import Scan

class ScanForm(forms.ModelForm):
   class Meta:
     model = Scan
     fields = '__all__'
     widgets = {
            'domain_name': forms.TextInput(attrs={'class': 'form-input mt-1 block w-full'}),
            'tapirus': forms.CheckboxInput(attrs={'class': 'form-checkbox mt-1'}),
            'goat': forms.CheckboxInput(attrs={'class': 'form-checkbox mt-1'}),
            'owl': forms.CheckboxInput(attrs={'class': 'form-checkbox mt-1'}),
            'kangaroo': forms.CheckboxInput(attrs={'class': 'form-checkbox mt-1'}),
            'badger': forms.CheckboxInput(attrs={'class': 'form-checkbox mt-1'}),
            'limit': forms.NumberInput(attrs={'class': 'form-input mt-1 block w-full'}),
            'dkim': forms.TextInput(attrs={'class': 'form-input mt-1 block w-full'}),
            'user': forms.Select(attrs={'class': 'form-select mt-1 block w-full'}),
        }