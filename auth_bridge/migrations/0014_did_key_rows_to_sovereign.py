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

from typing import Any

from django.db import migrations


def promote_did_key_rows(apps: Any, schema_editor: Any) -> None:
    User = apps.get_model('auth_bridge', 'User')
    (
        User.objects.filter(custodial_did__startswith='did:key:')
        .exclude(account_tier='sovereign', is_sovereign=True)
        .update(account_tier='sovereign', is_sovereign=True)
    )


class Migration(migrations.Migration):

    dependencies = [
        ('auth_bridge', '0013_user_merged_into'),
    ]

    operations = [
        migrations.RunPython(promote_did_key_rows, migrations.RunPython.noop),
    ]
