import os
import requests
from eveonline.managers import EveManager
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
            logger.debug(headers)
            logger.debug(endpoint)
            ret = getattr(requests, func)(endpoint, headers=headers, data=kwargs)
            return ret.json()
        except:
            logger.debug("Error encountered while performing api request to SeAT")
            return {}

    @staticmethod
    def add_user(username, email):
        """ Add user to service """
        sanatized = str(SeatManager.__santatize_username(username))
        logger.debug("Adding user to SeAT with username %s" % sanatized)
        password = SeatManager.__generate_random_pass()
        ret = SeatManager.exec_request('user', 'post', username=sanatized, email=str(email), password=password)
        logger.debug(ret)
        logger.info("Added SeAT user with username %s" % sanatized)
        return sanatized, password

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
        ret = SeatManager.exec_request('user/' + username, 'put', active=0)
        SeatManager.update_roles(username, [])
        logger.debug(ret)
        logger.info("Disabled SeAT user with username %s" % username)
        return username

    @staticmethod
    def enable_user(username):
        """ Enable user """
        ret = SeatManager.exec_request('user/' + username, 'put', active=1)
        logger.debug(ret)
        logger.info("Enabled SeAT user with username %s" % username)
        return username

    @staticmethod
    def update_user(username, email, password):
        """ Edit user info """
        logger.debug("Updating SeAT username %s with email %s and password hash starting with %s" % (username, email,
                                                                                                     password[0:5]))
        ret = SeatManager.exec_request('user/' + username, 'put', email=email)
        logger.debug(ret)
        ret = SeatManager.exec_request('user/' + username, 'put', password=password)
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

    @staticmethod
    def check_user_status(username):
        sanatized = str(SeatManager.__santatize_username(username))
        logger.debug("Checking SeAT status for user %s" % sanatized)
        ret = SeatManager.exec_request('user/' + sanatized, 'get')
        logger.debug(ret)
        return ret

    @staticmethod
    def synchronize_eveapis(api_user, seat_user):
        userinfo = SeatManager.check_user_status(seat_user)
        user_seat_eveapis = SeatManager.get_user_seat_eveapis(userinfo["id"])
        keypars = EveManager.get_api_key_pairs(api_user)
        if keypars:
            for keypar in keypars:
                if keypar.api_id not in user_seat_eveapis.keys():
                    logger.debug("Adding Api Key with ID %s" % keypar.api_id)
                    ret = SeatManager.exec_request('key', 'post', key_id=keypar.api_id, v_code=keypar.api_key)
                    logger.debug(ret)
                    logger.debug("Transferring Api Key with ID %s to user %s with ID %s " % (keypar.api_id, seat_user,
                                                                                             userinfo['id']))
                    ret = SeatManager.exec_request('key/transfer/' + keypar.api_id + '/' + userinfo['id'], 'get')
                    logger.debug(ret)
                else:
                    user_seat_eveapis.pop(keypar.api_id)
        if user_seat_eveapis:
            for key in user_seat_eveapis.iterkeys():
                logger.debug("Removing api key %s from SeAT database" % key)
                ret = SeatManager.exec_request('key' + "/" + key, 'delete')
                logger.debug(ret)

    @staticmethod
    def get_user_seat_eveapis(user_id):
        seat_all_keys = SeatManager.exec_request('key', 'get')
        seat_user_keys = {}
        for key in seat_all_keys:
            try:
                if key["user_id"] == user_id:
                    seat_user_keys[key["key_id"]] = key["v_code"]
            except KeyError:
                pass
        return seat_user_keys

    @staticmethod
    def get_all_roles():
        groups = {}
        ret = SeatManager.exec_request('role', 'get')
        logger.debug(ret)
        for group in ret:
            groups[group["title"]] = group["id"]
        logger.debug("Retrieved role list from SeAT: %s" % str(groups))
        return groups

    @staticmethod
    def add_role(role):
        ret = SeatManager.exec_request('role/new', 'post', name=role)
        logger.debug(ret)
        logger.info("Added Seat group %s" % role)
        role_info = SeatManager.exec_request('role/detail/' + role, 'get')
        logger.debug(role_info)
        return role_info["id"]

    @staticmethod
    def add_role_to_user(user_id, role_id):
        ret = SeatManager.exec_request('role/grant-user-role/' + user_id + "/" + role_id, 'get')
        logger.info("Added role %s to user %s" % (role_id, user_id))
        return ret

    @staticmethod
    def revoke_role_from_user(user_id, role_id):
        ret = SeatManager.exec_request('role/revoke-user-role/' + user_id + "/" + role_id, 'get')
        logger.info("Revoked role %s from user %s" % (role_id, user_id))
        return ret

    @staticmethod
    def update_roles(seat_user, roles):
        logger.debug("Updating SeAT user %s with roles %s" % (seat_user, roles))
        user_info = SeatManager.check_user_status(seat_user)
        user_roles = {}
        if type(user_info["roles"]) is list:
            for role in user_info["roles"]:
                user_roles[role["title"]] = role["id"]
        logger.debug("Got user %s SeAT roles %s" % (seat_user, user_roles))
        seat_roles = SeatManager.get_all_roles()
        addroles = set(roles) - set(user_roles.keys())
        remroles = set(user_roles.keys()) - set(roles)

        logger.info("Updating SeAT roles for user %s - adding %s, removing %s" % (seat_user, addroles, remroles))
        for r in addroles:
            if r not in seat_roles:
                seat_roles[r] = SeatManager.add_role(r)
            logger.debug("Adding role %s to SeAT user %s" % (r, seat_user))
            SeatManager.add_role_to_user(user_info["id"], seat_roles[r])
        for r in remroles:
            logger.debug("Removing role %s from user %s" % (r, seat_user))
            SeatManager.revoke_role_from_user(user_info["id"], seat_roles[r])
