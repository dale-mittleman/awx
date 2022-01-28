from .plugin import CredentialPlugin
from django.utils.translation import ugettext_lazy as _

from thycotic.secrets.server import PasswordGrantAuthorizer, DomainPasswordGrantAuthorizer, SecretServer, ServerSecret

tss_inputs = {
    'fields': [
        {
            'id': 'server_url',
            'label': _('Secret Server URL'),
            'help_text': _('The Base URL of Secret Server e.g. https://myserver/SecretServer or https://mytenant.secretservercloud.com'),
            'type': 'string',
        },
        {
            'id': 'username',
            'label': _('Username'),
            'help_text': _('The (Application) user username'),
            'type': 'string',
        },
        {
            'id': 'password',
            'label': _('Password'),
            'help_text': _('The corresponding password'),
            'type': 'string',
            'secret': True,
        },
        {
            'id': 'domain',
            'label': _('Domain'),
            'help_text': _('The Active Directory domain the Secret Server is joined to (not relevant in all cases).'),
            'type': 'string',
        }
    ],
    'metadata': [
        {
            'id': 'secret_id',
            'label': _('Secret ID'),
            'help_text': _('The integer ID of the secret'),
            'type': 'string',
        },
        {
            'id': 'secret_field',
            'label': _('Secret Field'),
            'help_text': _('The field to extract from the secret'),
            'type': 'string',
        },
    ],
    'required': ['server_url', 'username', 'password', 'secret_id', 'secret_field'],
}


def tss_backend(**kwargs):
    server_url = kwargs['server_url']
    username = kwargs['username']
    password = kwargs['password']
    secret_id = kwargs['secret_id']
    secret_field = kwargs['secret_field']
    
    domain = None
    if 'domain' in kwargs.keys():
        domain = kwargs['domain']

    if 'domain' is not None:
        authorizer = DomainPasswordGrantAuthorizer(server_url, username, domain, password)
    else:
        authorizer = PasswordGrantAuthorizer(server_url, username, password)

    secret_server = SecretServer(server_url, authorizer)
    secret_dict = secret_server.get_secret(secret_id)
    secret = ServerSecret(**secret_dict)

    return secret.fields[secret_field]


tss_plugin = CredentialPlugin(
    'Thycotic Secret Server',
    tss_inputs,
    tss_backend,
)
