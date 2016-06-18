import os
import requests
from hashlib import md5

from django.conf import settings

import logging

logger = logging.getLogger(__name__)

class SeatManager:
    def __init__(self):
        pass

    @staticmethod
    def __santatize_username(username):
        sanatized = username.replace(" ", "_")
        return sanatized.lower()

    @staticmethod
    def __generate_random_pass():
        return os.urandom(8).encode('hex')

    @staticmethod
    def exec_request(endpoint, func, **kwargs):
        """ Send an https api request """
        try:
            endpoint = settings.SEAT_URL + '/api/v1/' + endpoint
            headers = {'X-Token': settings.SEAT_XTOKEN, 'Accept': 'application/json'}
            ret = getattr(requests, func)(endpoint, headers=headers, data=kwargs)
            return ret.json
        except:
            return {}

    @staticmethod
    def add_user(username, email):
        """ Add user to service """
        sanatized = str(SeatManager.__santatize_username(username))
        logger.debug("Adding user to SeAT with username %s" % sanatized)
        plain_password = SeatManager.__generate_random_pass()
        password = md5(plain_password).hexdigest()
        ret = SeatManager.exec_request('user', 'post', username=sanatized, email=str(email), password=password)
        logger.debug(ret)
        logger.info("Added SeAT user with username %s" % sanatized)
        return sanatized, plain_password

    @staticmethod
    def delete_user(username):
        """ Delete user """
        ret = SeatManager.exec_request('user/' + username, 'delete')
        logger.debug(ret)
        logger.info("Deleted SeAT user with username %s" % username)
        return username

    @staticmethod
    def disable_user(username):
        """ Disable user """
        ret = SeatManager.exec_request('user' + username, 'put',  active=0)
        logger.debug(ret)
        logger.info("Disabled SeAT user with username %s" % username)
        return username

    @staticmethod
    def update_user(username, email, password):
        """ Edit user info """
        password = md5(password).hexdigest()
        logger.debug("Updating SeAT username %s with email %s and password hash starting with %s" % (username, email,
                                                                                                     password[0:5]))
        ret = SeatManager.exec_request('user' + username, 'put', username=username, email=email, password=password)
        logger.debug(ret)
        logger.info("Updated SeAT user with username %s" % username)
        return username

    @staticmethod
    def update_user_password(username, email, plain_password=None):
        logger.debug("Settings new SeAT password for user %s" % username)
        if not plain_password:
            plain_password = SeatManager.__generate_random_pass()
        SeatManager.update_user(username, email, plain_password)
        return plain_password

#    @staticmethod
#    def get_all_groups():
#        groups = []
#        ret = IPBoardManager.exec_xmlrpc('getAllGroups')
#        for group in ret:
#            groups.append(group["g_title"])
#        logger.debug("Retrieved group list from IPBoard: %s" % groups)
#        return groups

#    @staticmethod
#    def get_user_groups(username):
#        groups = []
#        ret = IPBoardManager.exec_xmlrpc('getUserGroups', username=username)
#        if type(ret) is list:
#            for group in ret:
#                groups.append(group["g_title"])
#        logger.debug("Got user %s IPBoard groups %s" % (username, groups))
#        return groups

#    @staticmethod
#    def add_group(group):
#        ret = IPBoardManager.exec_xmlrpc('addGroup', group=group)
#        logger.info("Added IPBoard group %s" % group)
#        return ret

#    @staticmethod
#    def add_user_to_group(username, group):
#        ret = IPBoardManager.exec_xmlrpc('addUserToGroup', username=username, group=group)
#        logger.info("Added IPBoard user %s to group %s" % (username, group))
#        return ret

#    @staticmethod
#    def remove_user_from_group(username, group):
#        ret = IPBoardManager.exec_xmlrpc('removeUserFromGroup', username=username, group=group)
#        logger.info("Removed IPBoard user %s from group %s" % (username, group))
#        return ret

#    @staticmethod
#    def help_me():
#        "Random help me"
#        ret = IPBoardManager.exec_xmlrpc('helpMe')
#        return ret

#    @staticmethod
#    def update_groups(username, groups):
#        logger.debug("Updating IPBoard user %s with groups %s" % (username, groups))
#        forum_groups = IPBoardManager.get_all_groups()
#        user_groups = set(IPBoardManager.get_user_groups(username))
#        act_groups = set([g.replace(' ', '-') for g in groups])
#        addgroups = act_groups - user_groups
#        remgroups = user_groups - act_groups

#        logger.info("Updating IPBoard groups for user %s - adding %s, removing %s" % (username, addgroups, remgroups))
#        for g in addgroups:
#            if not g in forum_groups:
#                IPBoardManager.add_group(g)
#            logger.debug("Adding user %s to IPBoard group %s" % (username, g))
#            IPBoardManager.add_user_to_group(username, g)

#        for g in remgroups:
#            logger.debug("Removing user %s from IPBoard group %s" % (username, g))
#            IPBoardManager.remove_user_from_group(username, g)


