from django import forms
from django.conf import settings

from services.managers.eve_api_manager import EveApiManager
from eveonline.managers import EveManager
from eveonline.models import EveCharacter
import evelink

from celerytask.tasks import determine_membership_by_character

import logging

logger = logging.getLogger(__name__)

class UpdateKeyForm(forms.Form):
    user_state = None

    api_id = forms.CharField(max_length=254, required=True, label="Key ID")
    api_key = forms.CharField(max_length=254, required=True, label="Verification Code")
    
    def clean_api_id(self):
        try:
            api_id = int(self.cleaned_data['api_id'])
            return api_id
        except:
            raise forms.ValidationError("API ID must be a number")

    def clean(self):
        super(UpdateKeyForm, self).clean()

        if 'api_id' in self.cleaned_data and 'api_key' in self.cleaned_data:
            try:
                if EveManager.check_if_api_key_pair_exist(self.cleaned_data['api_id']):
                    logger.debug("UpdateKeyForm failed cleaning as API id %s already exists." % self.cleaned_data['api_id'])
                    raise forms.ValidationError(u'API key already exist')
                if EveApiManager.api_key_is_valid(self.cleaned_data['api_id'], self.cleaned_data['api_key']) is False:
                    raise forms.ValidationError(u'API key is invalid')
                if (settings.REJECT_OLD_APIS and
                    EveManager.check_if_api_key_pair_is_new(self.cleaned_data['api_id'], settings.REJECT_OLD_APIS_MARGIN) is False):
                    raise forms.ValidationError(u'API key is too old. Please create a new key')
                chars = EveApiManager.get_characters_from_api(self.cleaned_data['api_id'], self.cleaned_data['api_key']).result
                states = []
                states.append(self.user_state)
                for char in chars:
                    evechar = EveCharacter()
                    evechar.character_name = chars[char]['name']
                    evechar.corporation_id = chars[char]['corp']['id']
                    evechar.alliance_id = chars[char]['alliance']['id']
                    state = determine_membership_by_character(evechar)
                    logger.debug("API ID %s character %s has state %s" % (self.cleaned_data['api_id'], evechar, state))
                    states.append(state)

                if 'MEMBER' in states:
                    if EveApiManager.validate_member_api(self.cleaned_data['api_id'], self.cleaned_data['api_key']) is False:
                        raise forms.ValidationError(u'API must meet member requirements')
                if 'BLUE' in states:
                    if EveApiManager.validate_blue_api(self.cleaned_data['api_id'], self.cleaned_data['api_key']) is False:
                        raise forms.ValidationError(u'API must meet blue requirements')
                return self.cleaned_data
            except evelink.api.APIError as e:
                logger.debug("Got error code %s while validating API %s" % (e.code, self.cleaned_data['api_id']))
                if int(e.code) in [221, 222]:
                    raise forms.ValidationError("API key failed validation")
                else:
                    raise forms.ValidationError("Failed to reach API servers")
