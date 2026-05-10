from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):

    ROLE_CHOICES = (
        ('student', 'Student'),
        ('teacher', 'Teacher'),
        ('manager', 'Manager'),
        ('admin', 'Admin'),
    )

    email = models.EmailField(unique=True)
    role = models.CharField( max_length=20, choices=ROLE_CHOICES, default='student' )
    phone = models.CharField(max_length=20, blank=True, null=True)
    image = models.ImageField( upload_to='users/', blank=True, null=True )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.email