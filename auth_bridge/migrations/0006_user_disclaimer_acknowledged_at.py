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
        ('auth_bridge', '0005_user_show_legal_disclaimer'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='disclaimer_acknowledged_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
