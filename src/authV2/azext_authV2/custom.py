# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import json
from re import A
import re
from knack.prompting import prompt_y_n
from knack.util import CLIError
from azure.cli.core.util import send_raw_request, shell_safe_json_parse
from azure.cli.command_modules.appservice._appservice_utils import _generic_site_operation
from azure.cli.command_modules.appservice.custom import update_app_settings
from azure.cli.core.azclierror import ArgumentUsageError
from azure.cli.core.commands.client_factory import get_subscription_id
from azure.cli.command_modules.appservice._params import AUTH_TYPES
from azure.cli.core.cloud import AZURE_PUBLIC_CLOUD, AZURE_CHINA_CLOUD, AZURE_US_GOV_CLOUD, AZURE_GERMAN_CLOUD
from azure.mgmt.web.models import SiteAuthSettingsV2

MICROSOFT_SECRET_SETTING_NAME = "MICROSOFT_PROVIDER_AUTHENTICATION_SECRET"
FACEBOOK_SECRET_SETTING_NAME = "FACEBOOK_PROVIDER_AUTHENTICATION_SECRET"
GITHUB_SECRET_SETTING_NAME = "GITHUB_PROVIDER_AUTHENTICATION_SECRET"
GOOGLE_SECRET_SETTING_NAME = "GOOGLE_PROVIDER_AUTHENTICATION_SECRET"
MSA_SECRET_SETTING_NAME = "MSA_PROVIDER_AUTHENTICATION_SECRET"
TWITTER_SECRET_SETTING_NAME = "TWITTER_PROVIDER_AUTHENTICATION_SECRET"
TRUE_STRING = "true"
FALSE_STRING = "false"


# region rest calls


def get_resource_id(cmd, resource_group_name, name, slot):
    sub_id = get_subscription_id(cmd.cli_ctx)

    # TODO: Replace ARM call with SDK API after fixing swagger issues
    resource_id = "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Web/sites/{}".format(
        sub_id,
        resource_group_name,
        name)
    if slot is not None:
        resource_id = resource_id + "/slots/" + slot
    return resource_id


def get_auth_settings_v2(cmd, resource_group_name, name, slot=None):
    return _generic_site_operation(cmd.cli_ctx, resource_group_name, name, 'get_auth_settings_v2', slot)


def update_auth_settings_v2_helper(cmd, resource_group_name, name, site_auth_settings_v2,
                                      slot=None, overwrite_settings=False, is_upgrade=False):  # pylint: disable=unused-argument
    is_using_v1 = get_config_version(cmd, resource_group_name, name, slot)["configVersion"] == 'v1'
    is_new_auth_app = is_app_new_to_auth(cmd, resource_group_name, name, slot)

    if not is_upgrade and is_using_v1 and not is_new_auth_app:
        msg = 'Usage Error: Cannot use auth v2 commands when the app is using auth v1. ' \
              'Update the auth settings using the az webapp auth-classic command group.'
        raise CLIError(msg)

    if not overwrite_settings:  # if no auth v2 settings set, then default token store to true
        if is_new_auth_app:
            if not getattr(site_auth_settings_v2, "login", None):
                setattr(site_auth_settings_v2, "login", cmd.get_models("Login"))
            if not getattr(site_auth_settings_v2.login, "token_store", None):
                setattr(site_auth_settings_v2.login, "token_store", cmd.get_models("TokenStore"))
            setattr(site_auth_settings_v2.login.token_store, "enabled", True)

    return _generic_site_operation(cmd.cli_ctx, resource_group_name, name, 'update_auth_settings_v2', slot, site_auth_settings_v2)


def is_auth_v2_app(cmd, resource_group_name, name, slot=None):
    auth_settings = get_auth_settings(cmd, resource_group_name, name, slot)
    return getattr(auth_settings, "config_version", None) == "v2"
# endregion

# region webapp auth


def set_auth_settings_v2(cmd, resource_group_name, name, body=None, slot=None):  # pylint: disable=unused-argument
    if body is None:
        json_object = None
    else:
        json_object = json.loads(body)

    is_using_v1 = get_config_version(cmd, resource_group_name, name, slot)["configVersion"] == 'v1'
    is_new_auth_app = is_app_new_to_auth(cmd, resource_group_name, name, slot)

    if is_using_v1 and not is_new_auth_app:
        msg = 'Usage Error: Cannot use auth v2 commands when the app is using auth v1. ' \
              'Update the auth settings using the az webapp auth-classic command group.'
        raise CLIError(msg)

    final_json = {
        "properties": json_object
    }

    resource_id = get_resource_id(cmd, resource_group_name, name, slot)
    management_hostname = cmd.cli_ctx.cloud.endpoints.resource_manager
    request_url = "{}/{}/{}?api-version={}".format(
        management_hostname.strip('/'),
        resource_id,
        "config/authSettingsV2",
        "2020-12-01")

    # TODO: Replace ARM call with SDK API after fixing swagger issues
    r = send_raw_request(cmd.cli_ctx, "PUT", request_url, None, None, json.dumps(final_json))
    return r.json()["properties"]


def update_auth_settings_v2(cmd, resource_group_name, name, set_string=None, enabled=None,  # pylint: disable=unused-argument
                            runtime_version=None, config_file_path=None, unauthenticated_client_action=None,  # pylint: disable=unused-argument
                            redirect_provider=None, enable_token_store=None, require_https=None,  # pylint: disable=unused-argument
                            proxy_convention=None, proxy_custom_host_header=None,  # pylint: disable=unused-argument
                            proxy_custom_proto_header=None, excluded_paths=None, slot=None):  # pylint: disable=unused-argument
    existing_auth = get_auth_settings_v2(cmd, resource_group_name, name, slot)
    print("existing auth:", existing_auth)
    existing_auth = set_field_in_auth_settings(cmd, existing_auth, set_string)
    print("using extension method:", existing_auth)
    converted_object = shell_safe_json_parse(set_string)
    print("using core method:", converted_object)
    raise CLIError('Usage Error: Cannot use command az webapp auth upgrade when the app is using auth v2.')

    if enabled is not None:
        if not getattr(existing_auth, "platform", None):
            setattr(existing_auth, "platform", cmd.get_models("AuthPlatform"))
        setattr(existing_auth.platform, "enabled", enabled)

    if runtime_version is not None:
        if not getattr(existing_auth, "platform", None):
            setattr(existing_auth, "platform", cmd.get_models("AuthPlatform"))
        setattr(existing_auth.platform, "runtime_version", runtime_version)

    if config_file_path is not None:
        if not getattr(existing_auth, "platform", None):
            setattr(existing_auth, "platform", cmd.get_models("AuthPlatform"))
        setattr(existing_auth.platform, "config_file_path", config_file_path)

    if unauthenticated_client_action is not None:
        if not getattr(existing_auth, "global_validation", None):
            setattr(existing_auth, "global_validation", cmd.get_models("GlobalValidation"))
        setattr(existing_auth.global_validation, "unauthenticated_client_action", unauthenticated_client_action)

    if redirect_provider is not None:
        if not getattr(existing_auth, "global_validation", None):
            setattr(existing_auth, "global_validation", cmd.get_models("GlobalValidation"))
        setattr(existing_auth.global_validation, "redirect_to_provider", redirect_provider)

    if enable_token_store is not None:
        if not getattr(existing_auth, "login", None):
            setattr(existing_auth, "login", cmd.get_models("Login"))
        if not getattr(existing_auth.login, "token_store", None):
            setattr(existing_auth.login, "token_store", cmd.get_models("TokenStore"))
        setattr(existing_auth.login.token_store, "enabled", enable_token_store)

    if excluded_paths is not None:
        if not getattr(existing_auth, "global_validation", None):
            setattr(existing_auth, "global_validation", cmd.get_models("GlobalValidation"))
        excluded_paths_list_temp = excluded_paths.strip("][}{").replace(" ", "").split(",")
        excluded_paths_list = []
        for path in excluded_paths_list_temp:
            excluded_paths_list.append(path.strip("'"))
        setattr(existing_auth.global_validation, "excluded_paths", excluded_paths_list)

    existing_auth = update_http_settings_in_auth_settings(cmd, existing_auth, require_https,
                                                          proxy_convention, proxy_custom_host_header,
                                                          proxy_custom_proto_header)

    json_object = existing_auth
    return update_auth_settings_v2_helper(cmd, resource_group_name, name, json_object, slot)
# endregion

# region webapp auth config-version


def upgrade_to_auth_settings_v2(cmd, resource_group_name, name, slot=None):  # pylint: disable=unused-argument
    if is_auth_v2_app(cmd, resource_group_name, name, slot):
        raise CLIError('Usage Error: Cannot use command az webapp auth upgrade when the app is using auth v2.')
    prep_auth_settings_for_v2(cmd, resource_group_name, name, slot)
    site_auth_settings_v2 = get_auth_settings_v2(cmd, resource_group_name, name, slot)
    return update_auth_settings_v2_helper(cmd, resource_group_name, name,
                                             site_auth_settings_v2, slot, is_upgrade=True)


def get_config_version(cmd, resource_group_name, name, slot=None):  # pylint: disable=unused-argument
    isV2 = is_auth_v2_app(cmd, resource_group_name, name, slot)
    config_version = "v1"
    if isV2:
        config_version = "v2"
    return {
        "configVersion": config_version
    }


def revert_to_auth_settings(cmd, resource_group_name, name, slot=None):  # pylint: disable=unused-argument
    if not is_auth_v2_app(cmd, resource_group_name, name, slot):
        raise CLIError('Usage Error: Cannot use command az webapp auth revert when the app is using auth v1.')
    site_auth_settings = get_auth_settings(cmd, resource_group_name, name, slot)
    set_auth_settings_v2(cmd, resource_group_name, name, None, slot)
    site_auth_settings.enabled = TRUE_STRING if site_auth_settings.enabled else FALSE_STRING
    site_auth_settings.token_store_enabled = TRUE_STRING if site_auth_settings.token_store_enabled else FALSE_STRING
    action = None
    if site_auth_settings.unauthenticated_client_action == "AllowAnonymous":
        action = "AllowAnonymous"
    elif site_auth_settings.unauthenticated_client_action == "RedirectToLoginPage":
        if site_auth_settings.default_provider == "AzureActiveDirectory":
            action = "LoginWithAzureActiveDirectory"
        elif site_auth_settings.default_provider == "Facebook":
            action = "LoginWithFacebook"
        elif site_auth_settings.default_provider == "Google":
            action = "LoginWithGoogle"
        elif site_auth_settings.default_provider == "MicrosoftAccount":
            action = "LoginWithMicrosoftAccount"
        elif site_auth_settings.default_provider == "Twitter":
            action = "LoginWithTwitter"

    update_auth_classic_settings(cmd, resource_group_name, name, site_auth_settings.enabled, action,
                                 site_auth_settings.client_id, site_auth_settings.token_store_enabled,
                                 site_auth_settings.runtime_version,
                                 site_auth_settings.token_refresh_extension_hours,
                                 site_auth_settings.allowed_external_redirect_urls, site_auth_settings.client_secret,
                                 site_auth_settings.client_secret_certificate_thumbprint,
                                 site_auth_settings.allowed_audiences, site_auth_settings.issuer,
                                 site_auth_settings.facebook_app_id,
                                 site_auth_settings.facebook_app_secret, site_auth_settings.facebook_o_auth_scopes,
                                 site_auth_settings.twitter_consumer_key, site_auth_settings.twitter_consumer_secret,
                                 site_auth_settings.google_client_id, site_auth_settings.google_client_secret,
                                 site_auth_settings.google_o_auth_scopes,
                                 site_auth_settings.microsoft_account_client_id,
                                 site_auth_settings.microsoft_account_client_secret,
                                 site_auth_settings.microsoft_account_o_auth_scopes, slot,
                                 site_auth_settings.git_hub_client_id, site_auth_settings.git_hub_client_secret,
                                 site_auth_settings.git_hub_o_auth_scopes,
                                 site_auth_settings.client_secret_setting_name,
                                 site_auth_settings.facebook_app_secret_setting_name,
                                 site_auth_settings.google_client_secret_setting_name,
                                 site_auth_settings.microsoft_account_client_secret_setting_name,
                                 site_auth_settings.twitter_consumer_secret_setting_name,
                                 site_auth_settings.git_hub_client_secret_setting_name)
# endregion

# region helper methods


def is_app_new_to_auth(cmd, resource_group_name, name, slot):
    existing_site_auth_settings_v2 = get_auth_settings_v2(cmd, resource_group_name, name, slot)
    return getattr(existing_site_auth_settings_v2, "global_validation", None)


def set_field_in_auth_settings_recursive(cmd, field_name_split, field_value, auth_settings):
    if len(field_name_split) == 1:
        if not field_value.startswith('[') or not field_value.endswith(']'):
            auth_settings.field_name_split[0] = field_value
        else:
            field_value_list_string = field_value[1:-1]
            auth_settings.field_name_split[0] = field_value_list_string.split(",")
        return auth_settings

    remaining_field_names = field_name_split[1:]
    if not getattr(auth_settings, field_name_split[0], None):
        # TODO: try catch?
        setattr(auth_settings, field_name_split[0], cmd.get_models(field_name_split[0]))
    auth_settings.field_name_split[0] = set_field_in_auth_settings_recursive(cmd, remaining_field_names,
                                                                              field_value,
                                                                              auth_settings.field_name_split[0])
    return auth_settings


def set_field_in_auth_settings(cmd, auth_settings, set_string):
    if set_string is not None:
        split1 = set_string.split("=")
        fieldName = split1[0]
        fieldValue = split1[1]
        split2 = fieldName.split(".")
        auth_settings = set_field_in_auth_settings_recursive(cmd, split2, fieldValue, auth_settings)
    return auth_settings


def update_http_settings_in_auth_settings(cmd, auth_settings, require_https, proxy_convention,
                                          proxy_custom_host_header, proxy_custom_proto_header):

    if require_https is not None:
        if not getattr(auth_settings, "http_settings", None):
            setattr(auth_settings, "http_settings", cmd.get_models("HttpSettings"))
        setattr(auth_settings.http_settings, "require_https", require_https)

    if proxy_convention is not None:
        if not getattr(auth_settings, "http_settings", None):
            setattr(auth_settings, "http_settings", cmd.get_models("HttpSettings"))
        if not getattr(auth_settings.http_settings, "forward_proxy", None):
            setattr(auth_settings.http_settings, "forward_proxy", cmd.get_models("ForwardProxy"))
        setattr(auth_settings.http_settings.forward_proxy, "convention", proxy_convention)

    if proxy_custom_host_header is not None:
        if not getattr(auth_settings, "http_settings", None):
            setattr(auth_settings, "http_settings", cmd.get_models("HttpSettings"))
        if not getattr(auth_settings.http_settings, "forward_proxy", None):
            setattr(auth_settings.http_settings, "forward_proxy", cmd.get_models("ForwardProxy"))
        setattr(auth_settings.http_settings, "custom_host_header_name", proxy_custom_host_header)

    if proxy_custom_proto_header is not None:
        if not getattr(auth_settings, "http_settings", None):
            setattr(auth_settings, "http_settings", cmd.get_models("HttpSettings"))
        if not getattr(auth_settings.http_settings, "forward_proxy", None):
            setattr(auth_settings.http_settings, "forward_proxy", cmd.get_models("ForwardProxy"))
        setattr(auth_settings.http_settings, "custom_proto_header_name", proxy_custom_proto_header)

    return auth_settings


def is_auth_runtime_version_valid(runtime_version=None):
    if runtime_version is None:
        return True
    if runtime_version.startswith("~") and len(runtime_version) > 1:
        try:
            int(runtime_version[1:])
        except ValueError:
            return False
        return True
    split_versions = runtime_version.split('.')
    if len(split_versions) != 3:
        return False
    for version in split_versions:
        try:
            int(version)
        except ValueError:
            return False
    return True


def prep_auth_settings_for_v2(cmd, resource_group_name, name, slot=None):  # pylint: disable=unused-argument
    site_auth_settings = get_auth_settings(cmd, resource_group_name, name, slot)
    settings = []
    if site_auth_settings.client_secret is not None:
        settings.append(MICROSOFT_SECRET_SETTING_NAME + '=' + site_auth_settings.client_secret)
        site_auth_settings.client_secret_setting_name = MICROSOFT_SECRET_SETTING_NAME
    if site_auth_settings.facebook_app_secret is not None:
        settings.append(FACEBOOK_SECRET_SETTING_NAME + '=' + site_auth_settings.facebook_app_secret)
        site_auth_settings.facebook_app_secret_setting_name = FACEBOOK_SECRET_SETTING_NAME
    if site_auth_settings.git_hub_client_secret is not None:
        settings.append(GITHUB_SECRET_SETTING_NAME + '=' + site_auth_settings.git_hub_client_secret)
        site_auth_settings.git_hub_client_secret_setting_name = GITHUB_SECRET_SETTING_NAME
    if site_auth_settings.google_client_secret is not None:
        settings.append(GOOGLE_SECRET_SETTING_NAME + '=' + site_auth_settings.google_client_secret)
        site_auth_settings.google_client_secret_setting_name = GOOGLE_SECRET_SETTING_NAME
    if site_auth_settings.microsoft_account_client_secret is not None:
        settings.append(MSA_SECRET_SETTING_NAME + '=' + site_auth_settings.microsoft_account_client_secret)
        site_auth_settings.microsoft_account_client_secret_setting_name = MSA_SECRET_SETTING_NAME
    if site_auth_settings.twitter_consumer_secret is not None:
        settings.append(TWITTER_SECRET_SETTING_NAME + '=' + site_auth_settings.twitter_consumer_secret)
        site_auth_settings.twitter_consumer_secret_setting_name = TWITTER_SECRET_SETTING_NAME
    if len(settings) > 0:
        update_app_settings(cmd, resource_group_name, name, slot=slot, slot_settings=settings)
        remove_all_auth_settings_secrets(cmd, resource_group_name, name, slot)
        update_auth_classic_settings(cmd, resource_group_name, name, site_auth_settings.enabled, None,
                                     site_auth_settings.client_id, site_auth_settings.token_store_enabled,
                                     site_auth_settings.runtime_version, site_auth_settings.token_refresh_extension_hours,
                                     site_auth_settings.allowed_external_redirect_urls, None,
                                     site_auth_settings.client_secret_certificate_thumbprint,
                                     site_auth_settings.allowed_audiences, site_auth_settings.issuer,
                                     site_auth_settings.facebook_app_id, None,
                                     site_auth_settings.facebook_o_auth_scopes,
                                     site_auth_settings.twitter_consumer_key, None,
                                     site_auth_settings.google_client_id, None,
                                     site_auth_settings.google_o_auth_scopes,
                                     site_auth_settings.microsoft_account_client_id,
                                     None,
                                     site_auth_settings.microsoft_account_o_auth_scopes, slot,
                                     site_auth_settings.git_hub_client_id, None,
                                     site_auth_settings.git_hub_o_auth_scopes,
                                     site_auth_settings.client_secret_setting_name,
                                     site_auth_settings.facebook_app_secret_setting_name,
                                     site_auth_settings.google_client_secret_setting_name,
                                     site_auth_settings.microsoft_account_client_secret_setting_name,
                                     site_auth_settings.twitter_consumer_secret_setting_name,
                                     site_auth_settings.git_hub_client_secret_setting_name)


def remove_all_auth_settings_secrets(cmd, resource_group_name, name, slot=None):  # pylint: disable=unused-argument
    auth_settings = get_auth_settings(cmd, resource_group_name, name, slot)
    auth_settings.client_secret = ""
    auth_settings.facebook_app_secret = ""
    auth_settings.git_hub_client_secret = ""
    auth_settings.google_client_secret = ""
    auth_settings.microsoft_account_client_secret = ""
    auth_settings.twitter_consumer_secret_setting_name = ""
    return _generic_site_operation(cmd.cli_ctx, resource_group_name, name,
                                   'update_auth_settings', slot, auth_settings)


def get_oidc_client_setting_app_setting_name(provider_name):
    provider_name_prefix = provider_name.upper()

    # an appsetting name can be up to 64 characters, and the suffix _PROVIDER_AUTHENTICATION_SECRET is 31 characters so limitting this to 32
    if len(provider_name_prefix) > 32:
        provider_name_prefix = provider_name_prefix[0:31]
    return provider_name_prefix + "_PROVIDER_AUTHENTICATION_SECRET"
# endregion

# region webapp auth-classic


def get_auth_settings(cmd, resource_group_name, name, slot=None):
    return _generic_site_operation(cmd.cli_ctx, resource_group_name, name, 'get_auth_settings', slot)


def update_auth_classic_settings(cmd, resource_group_name, name, enabled=None, action=None,  # pylint: disable=unused-argument
                                 client_id=None, token_store_enabled=None, runtime_version=None,  # pylint: disable=unused-argument
                                 token_refresh_extension_hours=None,  # pylint: disable=unused-argument
                                 allowed_external_redirect_urls=None, client_secret=None,  # pylint: disable=unused-argument
                                 client_secret_certificate_thumbprint=None,  # pylint: disable=unused-argument
                                 allowed_audiences=None, issuer=None, facebook_app_id=None,  # pylint: disable=unused-argument
                                 facebook_app_secret=None, facebook_oauth_scopes=None,  # pylint: disable=unused-argument
                                 twitter_consumer_key=None, twitter_consumer_secret=None,  # pylint: disable=unused-argument
                                 google_client_id=None, google_client_secret=None,  # pylint: disable=unused-argument
                                 google_oauth_scopes=None, microsoft_account_client_id=None,  # pylint: disable=unused-argument
                                 microsoft_account_client_secret=None,  # pylint: disable=unused-argument
                                 microsoft_account_oauth_scopes=None, slot=None,  # pylint: disable=unused-argument
                                 git_hub_client_id=None, git_hub_client_secret=None,  # pylint: disable=unused-argument
                                 git_hub_o_auth_scopes=None,  # pylint: disable=unused-argument
                                 client_secret_setting_name=None, facebook_app_secret_setting_name=None,  # pylint: disable=unused-argument
                                 google_client_secret_setting_name=None,  # pylint: disable=unused-argument
                                 microsoft_account_client_secret_setting_name=None,  # pylint: disable=unused-argument
                                 twitter_consumer_secret_setting_name=None, git_hub_client_secret_setting_name=None):  # pylint: disable=unused-argument
    if is_auth_v2_app(cmd, resource_group_name, name, slot):
        raise CLIError('Usage Error: Cannot use command az webapp auth-classic update when the app '
                       'is using auth v2. If you wish to revert the app to v1, run az webapp auth revert')

    auth_settings = get_auth_settings(cmd, resource_group_name, name, slot)
    if action == 'AllowAnonymous':
        auth_settings.unauthenticated_client_action = 'AllowAnonymous'
    elif action:
        auth_settings.unauthenticated_client_action = 'RedirectToLoginPage'
        auth_settings.default_provider = AUTH_TYPES[action]
    # validate runtime version
    if not is_auth_runtime_version_valid(runtime_version):
        raise CLIError('Usage Error: --runtime-version set to invalid value')

    import inspect
    frame = inspect.currentframe()
    bool_flags = ['enabled', 'token_store_enabled']
    # note: getargvalues is used already in azure.cli.core.commands.
    # and no simple functional replacement for this deprecating method for 3.5
    args, _, _, values = inspect.getargvalues(frame)  # pylint: disable=deprecated-method

    for arg in args[2:]:
        if values.get(arg, None):
            setattr(auth_settings, arg, values[arg] if arg not in bool_flags else values[arg] == 'true')

    return _generic_site_operation(cmd.cli_ctx, resource_group_name, name, 'update_auth_settings', slot, auth_settings)
# endregion

# region webapp auth microsoft


def get_aad_settings(cmd, resource_group_name, name, slot=None):
    auth_settings = get_auth_settings_v2(cmd, resource_group_name, name, slot)
    if not getattr(auth_settings, "identity_providers", None):
        return {}
    if not getattr(auth_settings.identity_providers, "azure_active_directory", None):
        return {}
    return auth_settings.identity_providers.azure_active_directory


def update_aad_settings(cmd, resource_group_name, name, slot=None,  # pylint: disable=unused-argument
                        client_id=None, client_secret_setting_name=None,  # pylint: disable=unused-argument
                        issuer=None, allowed_token_audiences=None, client_secret=None,  # pylint: disable=unused-argument
                        client_secret_certificate_thumbprint=None,  # pylint: disable=unused-argument
                        client_secret_certificate_san=None,  # pylint: disable=unused-argument
                        client_secret_certificate_issuer=None,  # pylint: disable=unused-argument
                        yes=False, tenant_id=None):    # pylint: disable=unused-argument
    # Validate parameters
    if client_secret is not None and client_secret_setting_name is not None:
        raise ArgumentUsageError('Usage Error: --client-secret and --client-secret-setting-name cannot both be '
                                 'configured to non empty strings')

    if client_secret_setting_name is not None and client_secret_certificate_thumbprint is not None:
        raise ArgumentUsageError('Usage Error: --client-secret-setting-name and --thumbprint cannot both be '
                                 'configured to non empty strings')

    if client_secret is not None and client_secret_certificate_thumbprint is not None:
        raise ArgumentUsageError('Usage Error: --client-secret and --thumbprint cannot both be '
                                 'configured to non empty strings')

    if client_secret is not None and client_secret_certificate_san is not None:
        raise ArgumentUsageError('Usage Error: --client-secret and --san cannot both be '
                                 'configured to non empty strings')

    if client_secret_setting_name is not None and client_secret_certificate_san is not None:
        raise ArgumentUsageError('Usage Error: --client-secret-setting-name and --san cannot both be '
                                 'configured to non empty strings')

    if client_secret_certificate_thumbprint is not None and client_secret_certificate_san is not None:
        raise ArgumentUsageError('Usage Error: --thumbprint and --san cannot both be '
                                 'configured to non empty strings')

    if ((client_secret_certificate_san is not None and client_secret_certificate_issuer is None) or
            (client_secret_certificate_san is None and client_secret_certificate_issuer is not None)):
        raise ArgumentUsageError('Usage Error: --san and --certificate-issuer must both be '
                                 'configured to non empty strings')

    if issuer is not None and (tenant_id is not None):
        raise ArgumentUsageError('Usage Error: --issuer and --tenant-id cannot be configured '
                                 'to non empty strings at the same time.')

    # Retrieve any existing auth settings
    is_new_aad_app = False
    existing_auth = get_auth_settings_v2(cmd, resource_group_name, name, slot)
    if not getattr(existing_auth, "identity_providers", None):
        setattr(existing_auth, "identity_providers", cmd.get_models("IdentityProviders"))
    if not getattr(existing_auth.identity_providers, "azure_active_directory", None):
        setattr(existing_auth.identity_providers, "azure_active_directory", cmd.get_models("AzureActiveDirectory"))
        is_new_aad_app = True

    if is_new_aad_app and issuer is None and tenant_id is None:
        raise CLIError('Usage Error: Either --issuer or --tenant-id must be specified when configuring the '
                       'Microsoft auth registration.')

    if client_secret is not None and not yes:
        msg = 'Configuring --client-secret will add app settings to the web app. Are you sure you want to continue?'
        if not prompt_y_n(msg, default="n"):
            raise CLIError('Usage Error: --client-secret cannot be used without agreeing to add app settings '
                           'to the web app.')

    openid_issuer = issuer
    if openid_issuer is None:
        # cmd.cli_ctx.cloud resolves to whichever cloud the customer is currently logged into
        authority = cmd.cli_ctx.cloud.endpoints.active_directory

        if tenant_id is not None:
            openid_issuer = authority + "/" + tenant_id + "/v2.0"

    # Create registration and validation objects using provided parameters
    registration = cmd.get_models("AzureActiveDirectoryRegistration")
    validation = cmd.get_models("AzureActiveDirectoryValidation")
    if (client_id is not None or client_secret is not None or
            client_secret_setting_name is not None or openid_issuer is not None or
            client_secret_certificate_thumbprint is not None or
            client_secret_certificate_san is not None or
            client_secret_certificate_issuer is not None):
        if not getattr(existing_auth.identity_providers.azure_active_directory, "registration", None):
            setattr(existing_auth.identity_providers.azure_active_directory, "registration", cmd.get_models("AzureActiveDirectoryRegistration"))
        registration = existing_auth.identity_providers.azure_active_directory.registration
    if allowed_token_audiences is not None:
        if not getattr(existing_auth.identity_providers.azure_active_directory, "validation", None):
            setattr(existing_auth.identity_providers.azure_active_directory, "validation", cmd.get_models("AzureActiveDirectoryValidation"))
        validation = existing_auth.identity_providers.azure_active_directory.validation

    if client_id is not None:
        setattr(registration, "client_id", client_id)
    if client_secret_setting_name is not None:
        setattr(registration, "client_secret_setting_name", client_secret_setting_name)
    if client_secret is not None:
        setattr(registration, "client_secret_setting_name", MICROSOFT_SECRET_SETTING_NAME)
        settings = []
        settings.append(MICROSOFT_SECRET_SETTING_NAME + '=' + client_secret)
        update_app_settings(cmd, resource_group_name, name, slot=slot, slot_settings=settings)
    if client_secret_setting_name is not None or client_secret is not None:
        if getattr(registration, "client_secret_certificate_thumbprint", None) is not None:
            setattr(registration, "client_secret_certificate_thumbprint", None)
        if getattr(registration, "client_secret_certificate_subject_alternative_name", None) is not None:
            setattr(registration, "client_secret_certificate_subject_alternative_name", None)
        if getattr(registration, "client_secret_certificate_issuer", None) is not None:
            setattr(registration, "client_secret_certificate_issuer", None)
    if client_secret_certificate_thumbprint is not None:
        setattr(registration, "client_secret_certificate_thumbprint", client_secret_certificate_thumbprint)
        if getattr(registration, "client_secret_setting_name", None) is not None:
            setattr(registration, "client_secret_setting_name", None)
        if getattr(registration, "client_secret_certificate_subject_alternative_name", None) is not None:
            setattr(registration, "client_secret_certificate_subject_alternative_name", None)
        if getattr(registration, "client_secret_certificate_issuer", None) is not None:
            setattr(registration, "client_secret_certificate_issuer", None)
    if client_secret_certificate_san is not None:
        setattr(registration, "client_secret_certificate_subject_alternative_name", client_secret_certificate_san)
    if client_secret_certificate_issuer is not None:
        setattr(registration, "client_secret_certificate_issuer", client_secret_certificate_issuer)
    if client_secret_certificate_san is not None and client_secret_certificate_issuer is not None:
        if getattr(registration, "client_secret_setting_name", None) is not None:
            setattr(registration, "client_secret_setting_name", None)
        if getattr(registration, "client_secret_certificate_thumbprint", None) is not None:
            setattr(registration, "client_secret_certificate_thumbprint", None)
    if openid_issuer is not None:
        setattr(registration, "open_id_issuer", openid_issuer)

    # Update registration and validation properties with newly created registration and validation objects
    if allowed_token_audiences is not None:
        setattr(validation, "allowed_audiences", allowed_token_audiences.split(","))
        setattr(existing_auth.identity_providers.azure_active_directory, "validation", validation)
    if (client_id is not None or client_secret is not None or
            client_secret_setting_name is not None or issuer is not None or
            client_secret_certificate_thumbprint is not None or
            client_secret_certificate_san is not None or
            client_secret_certificate_issuer is not None):
        setattr(existing_auth.identity_providers.azure_active_directory, "registration", registration)
    
    updated_auth_settings = update_auth_settings_v2_helper(cmd, resource_group_name, name, existing_auth, slot)
    return getattr(getattr(updated_auth_settings, "identity_providers", None), "azure_active_directory", None)
# endregion

# region webapp auth facebook


def get_facebook_settings(cmd, resource_group_name, name, slot=None):
    auth_settings = get_auth_settings_v2(cmd, resource_group_name, name, slot)
    if not getattr(auth_settings, "identity_providers", None):
        return {}
    if not getattr(auth_settings.identity_providers, "facebook", None):
        return {}
    return auth_settings.identity_providers.facebook


def update_facebook_settings(cmd, resource_group_name, name, slot=None,  # pylint: disable=unused-argument
                             app_id=None, app_secret_setting_name=None,  # pylint: disable=unused-argument
                             graph_api_version=None, scopes=None, app_secret=None, yes=False):    # pylint: disable=unused-argument
    # Validate parameters
    if app_secret is not None and app_secret_setting_name is not None:
        raise CLIError('Usage Error: --app-secret and --app-secret-setting-name cannot both be configured '
                       'to non empty strings')

    if app_secret is not None and not yes:
        msg = 'Configuring --app-secret will add app settings to the web app. Are you sure you want to continue?'
        if not prompt_y_n(msg, default="n"):
            raise CLIError('Usage Error: --app-secret cannot be used without agreeing to add app '
                           'settings to the web app.')

    # Retrieve any existing auth settings
    existing_auth = get_auth_settings_v2(cmd, resource_group_name, name, slot)
    if not getattr(existing_auth, "identity_providers", None):
        setattr(existing_auth, "identity_providers", cmd.get_models("IdentityProviders"))
    if not getattr(existing_auth.identity_providers, "facebook", None):
        setattr(existing_auth.identity_providers, "facebook", cmd.get_models("Facebook"))

    # Create registration object using provided parameters
    registration = cmd.get_models("AppRegistration")
    if app_id is not None or app_secret is not None or app_secret_setting_name is not None:
        if not getattr(existing_auth.identity_providers.facebook, "registration", None):
            setattr(existing_auth.identity_providers.facebook, "registration", cmd.get_models("AppRegistration"))
        registration = existing_auth.identity_providers.facebook.registration
    if scopes is not None:
        if not getattr(existing_auth.identity_providers.facebook, "login", None):
            setattr(existing_auth.identity_providers.facebook, "login", cmd.get_models("LoginScopes"))

    if app_id is not None:
        setattr(registration, "app_id", app_id)
    if app_secret_setting_name is not None:
        setattr(registration, "app_secret_setting_name", app_secret_setting_name)
    if app_secret is not None:
        setattr(registration, "app_secret_setting_name", FACEBOOK_SECRET_SETTING_NAME)
        settings = []
        settings.append(FACEBOOK_SECRET_SETTING_NAME + '=' + app_secret)
        update_app_settings(cmd, resource_group_name, name, slot=slot, slot_settings=settings)

    # Update registration property with newly created registration object
    if graph_api_version is not None:
        setattr(existing_auth.identity_providers.facebook, "graph_api_version", graph_api_version)
    if scopes is not None:
        setattr(existing_auth.identity_providers.facebook.login, "scopes", scopes.split(","))
    if app_id is not None or app_secret is not None or app_secret_setting_name is not None:
        setattr(existing_auth.identity_providers.facebook, "registration", registration)

    updated_auth_settings = update_auth_settings_v2_helper(cmd, resource_group_name, name, existing_auth, slot)
    return getattr(getattr(updated_auth_settings, "identity_providers", None), "facebook", None)
# endregion

# region webapp auth github


def get_github_settings(cmd, resource_group_name, name, slot=None):
    auth_settings = get_auth_settings_v2(cmd, resource_group_name, name, slot)["properties"]
    if "identityProviders" not in auth_settings.keys():
        return {}
    if "gitHub" not in auth_settings["identityProviders"].keys():
        return {}
    return auth_settings["identityProviders"]["gitHub"]


def update_github_settings(cmd, resource_group_name, name, slot=None,  # pylint: disable=unused-argument
                           client_id=None, client_secret_setting_name=None,  # pylint: disable=unused-argument
                           scopes=None, client_secret=None, yes=False):    # pylint: disable=unused-argument
    if client_secret is not None and client_secret_setting_name is not None:
        raise CLIError('Usage Error: --client-secret and --client-secret-setting-name cannot '
                       'both be configured to non empty strings')

    if client_secret is not None and not yes:
        msg = 'Configuring --client-secret will add app settings to the web app. Are you sure you want to continue?'
        if not prompt_y_n(msg, default="n"):
            raise CLIError('Usage Error: --client-secret cannot be used without agreeing to add '
                           'app settings to the web app.')

    existing_auth = get_auth_settings_v2(cmd, resource_group_name, name, slot)["properties"]
    registration = {}
    if "identityProviders" not in existing_auth.keys():
        existing_auth["identityProviders"] = {}
    if "gitHub" not in existing_auth["identityProviders"].keys():
        existing_auth["identityProviders"]["gitHub"] = {}
    if client_id is not None or client_secret is not None or client_secret_setting_name is not None:
        if "registration" not in existing_auth["identityProviders"]["gitHub"].keys():
            existing_auth["identityProviders"]["gitHub"]["registration"] = {}
        registration = existing_auth["identityProviders"]["gitHub"]["registration"]
    if scopes is not None:
        if "login" not in existing_auth["identityProviders"]["gitHub"].keys():
            existing_auth["identityProviders"]["gitHub"]["login"] = {}

    if client_id is not None:
        registration["clientId"] = client_id
    if client_secret_setting_name is not None:
        registration["clientSecretSettingName"] = client_secret_setting_name
    if client_secret is not None:
        registration["clientSecretSettingName"] = GITHUB_SECRET_SETTING_NAME
        settings = []
        settings.append(GITHUB_SECRET_SETTING_NAME + '=' + client_secret)
        update_app_settings(cmd, resource_group_name, name, slot=slot, slot_settings=settings)
    if scopes is not None:
        existing_auth["identityProviders"]["gitHub"]["login"]["scopes"] = scopes.split(",")
    if client_id is not None or client_secret is not None or client_secret_setting_name is not None:
        existing_auth["identityProviders"]["gitHub"]["registration"] = registration

    updated_auth_settings = update_auth_settings_v2_helper(cmd, resource_group_name, name, existing_auth, slot)
    return updated_auth_settings["identityProviders"]["gitHub"]
# endregion

# region webapp auth google


def get_google_settings(cmd, resource_group_name, name, slot=None):
    auth_settings = get_auth_settings_v2(cmd, resource_group_name, name, slot)["properties"]
    if "identityProviders" not in auth_settings.keys():
        return {}
    if "google" not in auth_settings["identityProviders"].keys():
        return {}
    return auth_settings["identityProviders"]["google"]


def update_google_settings(cmd, resource_group_name, name, slot=None,  # pylint: disable=unused-argument
                           client_id=None, client_secret_setting_name=None,  # pylint: disable=unused-argument
                           scopes=None, allowed_token_audiences=None, client_secret=None, yes=False):    # pylint: disable=unused-argument
    if client_secret is not None and client_secret_setting_name is not None:
        raise CLIError('Usage Error: --client-secret and --client-secret-setting-name cannot '
                       'both be configured to non empty strings')

    if client_secret is not None and not yes:
        msg = 'Configuring --client-secret will add app settings to the web app. Are you sure you want to continue?'
        if not prompt_y_n(msg, default="n"):
            raise CLIError('Usage Error: --client-secret cannot be used without agreeing to add '
                           'app settings to the web app.')

    existing_auth = get_auth_settings_v2(cmd, resource_group_name, name, slot)["properties"]
    registration = {}
    validation = {}
    if "identityProviders" not in existing_auth.keys():
        existing_auth["identityProviders"] = {}
    if "google" not in existing_auth["identityProviders"].keys():
        existing_auth["identityProviders"]["google"] = {}
    if client_id is not None or client_secret is not None or client_secret_setting_name is not None:
        if "registration" not in existing_auth["identityProviders"]["google"].keys():
            existing_auth["identityProviders"]["google"]["registration"] = {}
        registration = existing_auth["identityProviders"]["google"]["registration"]
    if scopes is not None:
        if "login" not in existing_auth["identityProviders"]["google"].keys():
            existing_auth["identityProviders"]["google"]["login"] = {}
    if allowed_token_audiences is not None:
        if "validation" not in existing_auth["identityProviders"]["google"].keys():
            existing_auth["identityProviders"]["google"]["validation"] = {}

    if client_id is not None:
        registration["clientId"] = client_id
    if client_secret_setting_name is not None:
        registration["clientSecretSettingName"] = client_secret_setting_name
    if client_secret is not None:
        registration["clientSecretSettingName"] = GOOGLE_SECRET_SETTING_NAME
        settings = []
        settings.append(GOOGLE_SECRET_SETTING_NAME + '=' + client_secret)
        update_app_settings(cmd, resource_group_name, name, slot=slot, slot_settings=settings)
    if scopes is not None:
        existing_auth["identityProviders"]["google"]["login"]["scopes"] = scopes.split(",")
    if allowed_token_audiences is not None:
        validation["allowedAudiences"] = allowed_token_audiences.split(",")
        existing_auth["identityProviders"]["google"]["validation"] = validation
    if client_id is not None or client_secret is not None or client_secret_setting_name is not None:
        existing_auth["identityProviders"]["google"]["registration"] = registration

    updated_auth_settings = update_auth_settings_v2_helper(cmd, resource_group_name, name, existing_auth, slot)
    return updated_auth_settings["identityProviders"]["google"]
# endregion

# region webapp auth twitter


def get_twitter_settings(cmd, resource_group_name, name, slot=None):
    auth_settings = get_auth_settings_v2(cmd, resource_group_name, name, slot)["properties"]
    if "identityProviders" not in auth_settings.keys():
        return {}
    if "twitter" not in auth_settings["identityProviders"].keys():
        return {}
    return auth_settings["identityProviders"]["twitter"]


def update_twitter_settings(cmd, resource_group_name, name, slot=None,  # pylint: disable=unused-argument
                            consumer_key=None, consumer_secret_setting_name=None,   # pylint: disable=unused-argument
                            consumer_secret=None, yes=False):    # pylint: disable=unused-argument
    if consumer_secret is not None and consumer_secret_setting_name is not None:
        raise CLIError('Usage Error: --consumer-secret and --consumer-secret-setting-name cannot '
                       'both be configured to non empty strings')

    if consumer_secret is not None and not yes:
        msg = 'Configuring --consumer-secret will add app settings to the web app. Are you sure you want to continue?'
        if not prompt_y_n(msg, default="n"):
            raise CLIError('Usage Error: --consumer-secret cannot be used without agreeing '
                           'to add app settings to the web app.')

    registration = {}
    existing_auth = get_auth_settings_v2(cmd, resource_group_name, name, slot)["properties"]
    if "identityProviders" not in existing_auth.keys():
        existing_auth["identityProviders"] = {}
    if "twitter" not in existing_auth["identityProviders"].keys():
        existing_auth["identityProviders"]["twitter"] = {}
    if consumer_key is not None or consumer_secret is not None or consumer_secret_setting_name is not None:
        if "registration" not in existing_auth["identityProviders"]["twitter"].keys():
            existing_auth["identityProviders"]["twitter"]["registration"] = {}
        registration = existing_auth["identityProviders"]["twitter"]["registration"]

    if consumer_key is not None:
        registration["consumerKey"] = consumer_key
    if consumer_secret_setting_name is not None:
        registration["consumerSecretSettingName"] = consumer_secret_setting_name
    if consumer_secret is not None:
        registration["consumerSecretSettingName"] = TWITTER_SECRET_SETTING_NAME
        settings = []
        settings.append(TWITTER_SECRET_SETTING_NAME + '=' + consumer_secret)
        update_app_settings(cmd, resource_group_name, name, slot=slot, slot_settings=settings)
    if consumer_key is not None or consumer_secret is not None or consumer_secret_setting_name is not None:
        existing_auth["identityProviders"]["twitter"]["registration"] = registration
    updated_auth_settings = update_auth_settings_v2_helper(cmd, resource_group_name, name, existing_auth, slot)
    return updated_auth_settings["identityProviders"]["twitter"]
# endregion

# region webapp auth apple


def get_apple_settings(cmd, resource_group_name, name, slot=None):
    auth_settings = get_auth_settings_v2(cmd, resource_group_name, name, slot)["properties"]
    if "identityProviders" not in auth_settings.keys():
        return {}
    if "apple" not in auth_settings["identityProviders"].keys():
        return {}
    return auth_settings["identityProviders"]["apple"]


def update_apple_settings(cmd, resource_group_name, name, slot=None,  # pylint: disable=unused-argument
                          client_id=None, client_secret_setting_name=None,  # pylint: disable=unused-argument
                          scopes=None, client_secret=None, yes=False):    # pylint: disable=unused-argument
    if client_secret is not None and client_secret_setting_name is not None:
        raise CLIError('Usage Error: --client-secret and --client-secret-setting-name '
                       'cannot both be configured to non empty strings')

    if client_secret is not None and not yes:
        msg = 'Configuring --client-secret will add app settings to the web app. ' \
            'Are you sure you want to continue?'
        if not prompt_y_n(msg, default="n"):
            raise CLIError('Usage Error: --client-secret cannot be used without agreeing '
                           'to add app settings to the web app.')

    existing_auth = get_auth_settings_v2(cmd, resource_group_name, name, slot)["properties"]
    registration = {}
    if "identityProviders" not in existing_auth.keys():
        existing_auth["identityProviders"] = {}
    if "apple" not in existing_auth["identityProviders"].keys():
        existing_auth["identityProviders"]["apple"] = {}
    if client_id is not None or client_secret is not None or client_secret_setting_name is not None:
        if "registration" not in existing_auth["identityProviders"]["apple"].keys():
            existing_auth["identityProviders"]["apple"]["registration"] = {}
        registration = existing_auth["identityProviders"]["apple"]["registration"]
    if scopes is not None:
        if "login" not in existing_auth["identityProviders"]["apple"].keys():
            existing_auth["identityProviders"]["apple"]["login"] = {}

    if client_id is not None:
        registration["clientId"] = client_id
    if client_secret_setting_name is not None:
        registration["clientSecretSettingName"] = client_secret_setting_name
    if client_secret is not None:
        registration["clientSecretSettingName"] = 'APPLE_PROVIDER_AUTHENTICATION_SECRET'
        settings = []
        settings.append('APPLE_PROVIDER_AUTHENTICATION_SECRET=' + client_secret)
        update_app_settings(cmd, resource_group_name, name, slot=slot, slot_settings=settings)
    if scopes is not None:
        existing_auth["identityProviders"]["apple"]["login"]["scopes"] = scopes.split(",")
    if client_id is not None or client_secret is not None or client_secret_setting_name is not None:
        existing_auth["identityProviders"]["apple"]["registration"] = registration

    updated_auth_settings = update_auth_settings_v2_helper(cmd, resource_group_name, name, existing_auth, slot)
    return updated_auth_settings["identityProviders"]["apple"]
# endregion

# region webapp auth openid-connect


def get_openid_connect_provider_settings(cmd, resource_group_name, name, provider_name, slot=None):  # pylint: disable=unused-argument
    auth_settings = get_auth_settings_v2(cmd, resource_group_name, name, slot)["properties"]
    if "identityProviders" not in auth_settings.keys():
        raise CLIError('Usage Error: The following custom OpenID Connect provider '
                       'has not been configured: ' + provider_name)
    if "customOpenIdConnectProviders" not in auth_settings["identityProviders"].keys():
        raise CLIError('Usage Error: The following custom OpenID Connect provider '
                       'has not been configured: ' + provider_name)
    if provider_name not in auth_settings["identityProviders"]["customOpenIdConnectProviders"].keys():
        raise CLIError('Usage Error: The following custom OpenID Connect provider '
                       'has not been configured: ' + provider_name)
    return auth_settings["identityProviders"]["customOpenIdConnectProviders"][provider_name]


def add_openid_connect_provider_settings(cmd, resource_group_name, name, provider_name, slot=None,  # pylint: disable=unused-argument
                                         client_id=None, client_secret_setting_name=None,  # pylint: disable=unused-argument
                                         openid_configuration=None, scopes=None,        # pylint: disable=unused-argument
                                         client_secret=None, yes=False):    # pylint: disable=unused-argument
    if client_secret is not None and not yes:
        msg = 'Configuring --client-secret will add app settings to the web app. ' \
            'Are you sure you want to continue?'
        if not prompt_y_n(msg, default="n"):
            raise CLIError('Usage Error: --client-secret cannot be used without agreeing '
                           'to add app settings to the web app.')

    auth_settings = get_auth_settings_v2(cmd, resource_group_name, name, slot)["properties"]
    if "identityProviders" not in auth_settings.keys():
        auth_settings["identityProviders"] = {}
    if "customOpenIdConnectProviders" not in auth_settings["identityProviders"].keys():
        auth_settings["identityProviders"]["customOpenIdConnectProviders"] = {}
    if provider_name in auth_settings["identityProviders"]["customOpenIdConnectProviders"].keys():
        raise CLIError('Usage Error: The following custom OpenID Connect provider has already been '
                       'configured: ' + provider_name + '. Please use az webapp auth oidc update to '
                       'update the provider.')

    final_client_secret_setting_name = client_secret_setting_name
    if client_secret is not None:
        final_client_secret_setting_name = get_oidc_client_setting_app_setting_name(provider_name)
        settings = []
        settings.append(final_client_secret_setting_name + '=' + client_secret)
        update_app_settings(cmd, resource_group_name, name, slot=slot, slot_settings=settings)

    auth_settings["identityProviders"]["customOpenIdConnectProviders"][provider_name] = {
        "registration": {
            "clientId": client_id,
            "clientCredential": {
                "clientSecretSettingName": final_client_secret_setting_name
            },
            "openIdConnectConfiguration": {
                "wellKnownOpenIdConfiguration": openid_configuration
            }
        }
    }
    login = {}
    if scopes is not None:
        login["scopes"] = scopes.split(',')
    else:
        login["scopes"] = ["openid"]

    auth_settings["identityProviders"]["customOpenIdConnectProviders"][provider_name]["login"] = login

    updated_auth_settings = update_auth_settings_v2_helper(cmd, resource_group_name, name, auth_settings, slot)
    return updated_auth_settings["identityProviders"]["customOpenIdConnectProviders"][provider_name]


def update_openid_connect_provider_settings(cmd, resource_group_name, name, provider_name, slot=None,  # pylint: disable=unused-argument
                                            client_id=None, client_secret_setting_name=None,  # pylint: disable=unused-argument
                                            openid_configuration=None, scopes=None,  # pylint: disable=unused-argument
                                            client_secret=None, yes=False):    # pylint: disable=unused-argument
    if client_secret is not None and not yes:
        msg = 'Configuring --client-secret will add app settings to the web app. ' \
            'Are you sure you want to continue?'
        if not prompt_y_n(msg, default="n"):
            raise CLIError('Usage Error: --client-secret cannot be used without agreeing '
                           'to add app settings to the web app.')

    auth_settings = get_auth_settings_v2(cmd, resource_group_name, name, slot)["properties"]
    if "identityProviders" not in auth_settings.keys():
        raise CLIError('Usage Error: The following custom OpenID Connect provider '
                       'has not been configured: ' + provider_name)
    if "customOpenIdConnectProviders" not in auth_settings["identityProviders"].keys():
        raise CLIError('Usage Error: The following custom OpenID Connect provider '
                       'has not been configured: ' + provider_name)
    if provider_name not in auth_settings["identityProviders"]["customOpenIdConnectProviders"].keys():
        raise CLIError('Usage Error: The following custom OpenID Connect provider '
                       'has not been configured: ' + provider_name)

    custom_open_id_connect_providers = auth_settings["identityProviders"]["customOpenIdConnectProviders"]
    registration = {}
    if client_id is not None or client_secret_setting_name is not None or openid_configuration is not None:
        if "registration" not in custom_open_id_connect_providers[provider_name].keys():
            custom_open_id_connect_providers[provider_name]["registration"] = {}
        registration = custom_open_id_connect_providers[provider_name]["registration"]

    if client_secret_setting_name is not None or client_secret is not None:
        if "clientCredential" not in custom_open_id_connect_providers[provider_name]["registration"].keys():
            custom_open_id_connect_providers[provider_name]["registration"]["clientCredential"] = {}

    if openid_configuration is not None:
        if "openIdConnectConfiguration" not in custom_open_id_connect_providers[provider_name]["registration"].keys():
            custom_open_id_connect_providers[provider_name]["registration"]["openIdConnectConfiguration"] = {}

    if scopes is not None:
        if "login" not in auth_settings["identityProviders"]["customOpenIdConnectProviders"][provider_name].keys():
            custom_open_id_connect_providers[provider_name]["login"] = {}

    if client_id is not None:
        registration["clientId"] = client_id
    if client_secret_setting_name is not None:
        registration["clientCredential"]["clientSecretSettingName"] = client_secret_setting_name
    if client_secret is not None:
        final_client_secret_setting_name = get_oidc_client_setting_app_setting_name(provider_name)
        registration["clientSecretSettingName"] = final_client_secret_setting_name
        settings = []
        settings.append(final_client_secret_setting_name + '=' + client_secret)
        update_app_settings(cmd, resource_group_name, name, slot=slot, slot_settings=settings)
    if openid_configuration is not None:
        registration["openIdConnectConfiguration"]["wellKnownOpenIdConfiguration"] = openid_configuration
    if scopes is not None:
        custom_open_id_connect_providers[provider_name]["login"]["scopes"] = scopes.split(",")
    if client_id is not None or client_secret_setting_name is not None or openid_configuration is not None:
        custom_open_id_connect_providers[provider_name]["registration"] = registration
    auth_settings["identityProviders"]["customOpenIdConnectProviders"] = custom_open_id_connect_providers

    updated_auth_settings = update_auth_settings_v2_helper(cmd, resource_group_name, name, auth_settings, slot)
    return updated_auth_settings["identityProviders"]["customOpenIdConnectProviders"][provider_name]


def remove_openid_connect_provider_settings(cmd, resource_group_name, name, provider_name, slot=None):  # pylint: disable=unused-argument
    auth_settings = get_auth_settings_v2(cmd, resource_group_name, name, slot)["properties"]
    if "identityProviders" not in auth_settings.keys():
        raise CLIError('Usage Error: The following custom OpenID Connect provider '
                       'has not been configured: ' + provider_name)
    if "customOpenIdConnectProviders" not in auth_settings["identityProviders"].keys():
        raise CLIError('Usage Error: The following custom OpenID Connect provider '
                       'has not been configured: ' + provider_name)
    if provider_name not in auth_settings["identityProviders"]["customOpenIdConnectProviders"].keys():
        raise CLIError('Usage Error: The following custom OpenID Connect provider '
                       'has not been configured: ' + provider_name)
    auth_settings["identityProviders"]["customOpenIdConnectProviders"].pop(provider_name, None)
    update_auth_settings_v2_helper(cmd, resource_group_name, name, auth_settings, slot)
    return {}
# endregion
