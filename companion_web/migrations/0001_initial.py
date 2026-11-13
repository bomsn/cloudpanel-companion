from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = []

    operations = [
        migrations.CreateModel(
            name='SignIn',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('at', models.DateTimeField()),
                ('succeeded', models.BooleanField()),
                ('username', models.CharField(max_length=150)),
                ('ip', models.CharField(blank=True, max_length=45)),
                ('country', models.CharField(blank=True, max_length=2)),
                ('browser', models.CharField(max_length=80)),
                ('two_factor', models.BooleanField(default=False)),
                ('new_source', models.CharField(blank=True, max_length=7)),
                ('burst', models.PositiveIntegerField(default=0)),
            ],
            options={'indexes': [models.Index(fields=['succeeded', 'at'], name='signin_outcome_time')]},
        ),
    ]
