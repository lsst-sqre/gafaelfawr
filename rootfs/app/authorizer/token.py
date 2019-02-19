# This file is part of jwt_authorizer.
#
# Developed for the LSST Data Management System.
# This product includes software developed by the LSST Project
# (https://www.lsst.org).
# See the COPYRIGHT file at the top-level directory of this distribution
# for details of code ownership.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
from datetime import datetime, timedelta
from typing import Any, Dict

import jwt

from flask import current_app
from .config import ALGORITHM


def reissue_token(token: Dict[str, Any], aud=None):
    reissued_token = token.copy()
    reissued_token.update(
        exp=datetime.utcnow() + timedelta(current_app.config['OAUTH2_JWT_EXP']),
        iss=current_app.config["OAUTH2_JWT_ISS"],
        aud=aud,
        iat=datetime.utcnow(),
    )
    private_key = current_app.config['OAUTH2_JWT_KEY']
    headers = {}
    if current_app.config.get('OAUTH2_JWT_KEY_ID'):
        headers['kid'] = current_app.config.get('OAUTH2_JWT_KEY_ID')
    return jwt.encode(reissued_token, private_key, algorithm=ALGORITHM, headers=headers)
