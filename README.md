[![Python application](https://github.com/thenodon/gonb/actions/workflows/python-app.yml/badge.svg)](https://github.com/thenodon/gonb/actions/workflows/python-app.yml)
[![PyPI version](https://badge.fury.io/py/gonb.svg)](https://badge.fury.io/py/gonb)

gonb - A Grafana onboarding tool
---------------------------------
# Overview
Gonb enable continues provisioning and configuration of Grafana based on an IAM source system.
This includes the lifecycle of organizations, users and teams.   

Users should authenticate using some SSO provider, but gonb us the same SSO IAM system to configure users into different
Grafana organizations and teams. 
Gonb should be run using some scheduling tool to keep user in sync with the users definition in the IAM source.

A typical patterns supported are:
- Map users in an IAM group to a corresponding organization.
- Map users in an IAM group into an organization and team

In the later use case gonb also provide the creation of folders that are specific to a team. This support the 
model where different teams have their own folder to create dashboards and alerts separated from other teams.

The user model in the IAM system must be mapped to the Grafana model. The model include the objects for 
organization, team and user where teams and users are linked to an organization.


# Features
- Integration with different IAM solution using a provider pattern.
- Multiple providers could operate against same Grafana instance, but should not operate on the same organization.
- A user can belong to multiple organizations.
- Automatic add and remove of user from organization(s) based on the lifecycle in the IAM.
- Update users in Grafana if any attributes in the user's IAM "object" is changed, e.g. the role, email.
- Create organization if they do not exist in Grafana, default false.
- Automatic creation of team folder, folder with same name as team, if teams are created. Default folder permission
for team is Editor. 
- Team member lifecycle in the same way as for users in organization
- Manage permission for user with Grafana Admin (instance admin) rights. Default is false.
- Create folders and one level of subfolder. Top folders and subfolders can have different permissions for teams.

# Argument passing
The only way to pass arguments to gonb is by environment variables. Each provider must define their own and 
required environment variables, and they must be exposed by the interface method:

```python
def mandatory_env_vars(self) -> Dict[str, str]:
    pass
```

For the grafana integration the following 3 must exist and have valid values, the rest are optional:

- GONB_GRAFANA_URL 
- GONB_GRAFANA_USER
- GONB_GRAFANA_PASSWORD
- GONB_GRAFANA_CREATE_ORGS - Will create organization(s) if not exists, default `False`
- GONB_GRAFANA_ADMINS - will manage users Grafana admin rights, default `False`
- GONB_GRAFANA_MAIN_ORG - allow management of Grafana `Main Org.`, default `False`
- GONB_GRAFANA_TEAM_FOLDER - create team folder, default `True` 
- GONB_SSO_PROVIDER - specify if the provider is based on a IAM used for Grafana authentication, default `True`.
- GONB_GRAFANA_DELETE_EXTERNAL_AUTH_USERS - if set to `True` gonb will delete users that are not in the 
  source system, but have been created just by Grafana through the auth process. Default is `False`. 
  This options should typical only be used if all users are provisioned by gonb.

> If `GONB_SSO_PROVIDER` is True there is some updating operations that are not done by gonb, e.g. update a 
> user's name or email.  

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

# Set to true if organizations should be created if not existing
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
- The GONB_GRAFANA_USER must be a Grafana instance admin.
- If the GONB_GRAFANA_USER do not exist in an organization that is to be managed, the user is added as an organization 
admin. 



# Future
- Support for Grafana Enterprise options for RBAC and team sync groups
