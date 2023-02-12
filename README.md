[![Python application](https://github.com/thenodon/gonb/actions/workflows/python-app.yml/badge.svg)](https://github.com/thenodon/gonb/actions/workflows/python-app.yml)
[![PyPI version](https://badge.fury.io/py/gonb.svg)](https://badge.fury.io/py/gonb)

gonb - A Grafana onboarding tool
---------------------------------
# Overview
Gnob enable continues provisioning and configuration of Grafana users to manage users lifecycle based on an IAM source 
system.

Users should authenticate using some SSO provider, but gnob us the same SSO IAM system to configure users into different
Grafana organizations. 
Gnob should be run using some scheduling tool to keep user in sync with the users definition in the IAM source.

A typical pattern is to map users in an IAM group to a corresponding organisation.

The user model in the IAM system must be mapped to the Grafana User model. The model include the 
following attributes:

- name - A "real" name of the user, e.g. first and last name
- email - users email
- login - the "username" - must be the same as the username for the SSO
- role - Can be Viewer, Editor or Admin, default Viewer
- password - The password can only be set when a user is added and should only be used for providers that are not
related to a SSO provider, since the authentication to Grafana is done by the SSO provider. 

> The password is default set to a 30 character random string of a mix of characters, numbers and special characters.


# Features
- Integration with different IAM solution using a provider pattern.
- A user can belong to multiple organisations.
- Automatic add and remove of user from organisation(s) based on the lifecycle in the IAM.
- Update user in Grafana if any attributes in the user's IAM "object" is changed, e.g. the role, email.
- Create organisation if they do not exists in Grafana, default false.

# Argument passing
The only way to pass arguments to gnob is by environment variables. Each provider must define their own and 
required environment variables and they must be exposed by the interface method:

```python
def mandatory_env_vars(self) -> Dict[str, str]:
    pass
```

For the grafana integration the following 3 must exist and have valid values:

- GONB_GRAFANA_URL
- GONB_GRAFANA_USER
- GONB_GRAFANA_PASSWORD
- GONB_GRAFANA_CREATE_ORGS - Will create organisation(s) if not exists, default `False`

# Develop a provider
A provider must implement the class `gonb.provider.Provider` and implement the following methods:
```python
    def get_users(self) -> Dict[str, Organization]:
    

    def mandatory_env_vars(self) -> Dict[str, str]:

```
If not implemented a `NotImplementedError` will be raised.

Please see examples in the directory `json_gonb_provider` and `okta_gonb_provider`.

> Both these example providers are part of gonb pip package https://pypi.org/project/gonb.

# Running gonb
There are two ways you can use gonb. The first is to use it as package and build a provider. 
The other way is to let gonb execute the provider. In this case the provider must be a python package and the 
following environment variables must be set before gonb is executed:
- GONB_PROVIDER_CLASS_PATH  - the class name that is a subclass to `Provider`, e.g. `json_gonb_provider.json_file.JSONFile`
where `json_gonb_provider.json_file` is the package part.

Gonb will dynamical load the module an instantiate the implemented `Provider` class.
The second option enable building different providers as packages and use, e.g. pip to deploy dependency.

>Of course, you can use both gonb and a provider as packages and build something totally new like web service 
>that sync on external events.

# Run the json provider example
The json file provider is just for testing. 

```shell
git clone git@github.com:thenodon/gonb.git
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt

export GONB_GRAFANA_PASSWORD=xyz
export GONB_GRAFANA_URL=http://localhost:3000
export GONB_GRAFANA_USER=admin
export GONB_JSON_FILE=json_file_example/users.json;

# Set to true if organisations should be created if not existing
export GONB_GRAFANA_CREATE_ORGS=true

cp json_file_example/users_add.json json_file_example/users.json
python -m json_gonb_provider

# check your Grafana for results
```
# System requirements

Python 3.8
Grafana 9 - tested on 9.3.6

# Future
- Add additional mapping for teams
