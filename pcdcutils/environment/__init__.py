#
# pcdcutils.environment
#
from os import environ


def is_env_enabled(env_setting=''):
    '''
    checks a string boolean environment setting
    returns python bool true|false whether it's enabled
    '''
    return (
        environ.get(env_setting, '').lower() in ['true', 't', '1', 'yes', 'y', 'on']
    )
