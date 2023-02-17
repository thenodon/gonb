[![Python application](https://github.com/thenodon/gonb/actions/workflows/python-app.yml/badge.svg)](https://github.com/thenodon/gonb/actions/workflows/python-app.yml)
[![PyPI version](https://badge.fury.io/py/gonb.svg)](https://badge.fury.io/py/gonb)

gonb - A Grafana onboarding tool
---------------------------------
# Overview
Gonb enable continues provisioning and configuration of Grafana based on an IAM source system.
This includes the lifecycle of organisations, users and teams.   

Users should authenticate using some SSO provider, but gonb us the same SSO IAM system to configure users into different
Grafana organizations and teams. 
Gonb should be run using some scheduling tool to keep user in sync with the users definition in the IAM source.

A typical patterns supported are:
- Map users in an IAM group to a corresponding organisation.
- Map users in an IAM group into a organisation and team

In the later use case gonb also provide the creation of folders that are specific to a team. This support the 
model where different teams have their own folder to create dashboards and alerts separated from other teams.

The user model in the IAM system must be mapped to the Grafana model. The model include the objects for 
organisation, team and user where teams and users are linked to an organisation.


# Features
- Integration with different IAM solution using a provider pattern.
- Multiple providers could operate against same Grafana instance, but should not operate on the same organisation.
- A user can belong to multiple organisations.
- Automatic add and remove of user from organisation(s) based on the lifecycle in the IAM.
- Update users in Grafana if any attributes in the user's IAM "object" is changed, e.g. the role, email.
- Create organisation if they do not exist in Grafana, default false.
- Automatic creation of team folder, folder with same name as team, if teams are created. Default folder permission
for team is Editor. 
- Team member lifecycle in the same way as for users in organisation

# Argument passing
The only way to pass arguments to gonb is by environment variables. Each provider must define their own and 
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
    def get_organisations(self) -> Dict[str, OrganizationDTO]:
    

    def mandatory_env_vars(self) -> Dict[str, str]:

```
If not implemented a `NotImplementedError` will be raised.

Please see examples in the directory `json_gonb_provider`, `json_team_gonb_provider` and `okta_gonb_provider`.

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

- Python 3.8
- Grafana 9 - tested on 9.3.6

# Important notes
- Password can be set by the provider, but should typical not since SSO would typical be used. 
The default is to set the password to a 30 character random string of a mix of characters, 
numbers and special characters.


# Future
- Support for Grafana Enterprise options for RBAC and team sync groups
