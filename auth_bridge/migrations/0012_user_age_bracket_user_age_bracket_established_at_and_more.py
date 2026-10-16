# Copyright (C) 2026 David Byers dba Byers Brands
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth_bridge', '0011_linkedemail'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='age_bracket',
            field=models.CharField(blank=True, choices=[('U14', 'Under 14'), ('U14-U18', '14-17'), ('ADULT', '18+')], db_index=True, max_length=16, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='age_bracket_established_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='parent_guardian_did',
            field=models.CharField(blank=True, db_index=True, max_length=255, null=True),
        ),
    ]
