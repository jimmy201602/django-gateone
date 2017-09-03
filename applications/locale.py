# -*- coding: utf-8 -*-
__doc__ = """
.. _locale.py:

Locale Module for Gate One
==========================

This module contains functions that deal with Gate One's locale, localization,
and internationalization features.
"""

from django.utils.translation import gettext_lazy
supported_locales = ['gateone.pot', 'gateone_js.pot']
from django.utils import translation
#user_language = 'zh-hans'
##user_language = 'en'
#translation.activate(user_language)
def get_translation(settings_dir=None):
    return gettext_lazy