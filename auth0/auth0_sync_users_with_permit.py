from dotenv import load_dotenv
import csv
import logging
import os
from permit import Permit
from auth0.v3.management import Auth0
import requests
import asyncio
import click

load_dotenv()

# auth0
auth0_domain = os.getenv('AUTH0_DOMAIN')
auth0_mgmt_access_token = os.getenv('AUTH0_MGMT_ACCESS_TOKEN')
# permit
permit_api_key = os.getenv('PERMIT_SDK_TOKEN', "")


class PermitAuth0Syncer:

    def __init__(self, csv_file, tenant_key):
        self.auth0_client = Auth0(auth0_domain, auth0_mgmt_access_token)
        self.permit_client = Permit(
        pdp="https://cloudpdp.api.permit.io",
        token=permit_api_key
        )
        self.loop = asyncio.get_event_loop()
        self.csv_file = csv_file
        self.tenant_key = tenant_key

    # get user roles from auth0
    def get_user_roles_from_auth0(self, user_id):
        user_roles = self.auth0_client.users.list_roles(user_id)
        return user_roles['roles']

    # get all available roles from permit
    def get_all_roles_from_permit(self):
        roles = self.loop.run_until_complete(self.permit_client.api.list_roles())
        return roles

    # create permit user
    async def create_permit_user(self, user_info, roles):
        # create a user
        user_obj = {
            "email": user_info['email'],
            "first_name": user_info['given_name'],
            "last_name": user_info['family_name'],
            "key": user_info['user_id'],
        }
        user = await self.permit_client.api.sync_user(user_obj)
        logging.info(f"Created user: {user}")
        # assign roles to the user
        if roles:
            for role in roles:
                user_role = await self.permit_client.api.assign_role(user_key=user.key, role_key=role['name'], tenant_key=self.tenant_key)
                logging.info(f"Assigned roles: {roles} to user: {user.key}")


    def get_auth0_roles(self, auth0_domain):
        roles_url = f'https://{auth0_domain}/api/v2/roles'
        roles_headers = {
            'Authorization': f'Bearer {auth0_mgmt_access_token}'
        }
        roles_response = requests.get(roles_url, headers=roles_headers)
        roles_data = roles_response.json()

        if roles_response.status_code == 200:
            return roles_data
        else:
            raise Exception(f'Failed to retrieve roles. Status code: {roles_response.status_code}, Error: {roles_data["message"]}')

    def sync_users(self):
        # iterate over user_id's and get user info from auth0 and create a permit user with the info
        with open(self.csv_file, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for user_info in reader:
                # get roles for user from auth0
                user_roles = self.get_user_roles_from_auth0(user_info['user_id'])
                # create permit user
                self.loop.run_until_complete(self.create_permit_user(user_info, user_roles))
    
    def create_missing_roles_in_permit(self, missing_roles):
        for role in missing_roles:
            role_obj = {
                "key": role,
                "name": role,
                "description": role
            }
            role = self.loop.run_until_complete(self.permit_client.api.create_role(role_obj))
            logging.info(f"Created role: {role}")


def main(csv_file, tenant_key):
    auth0_permit_syncer = PermitAuth0Syncer(csv_file=csv_file, tenant_key=tenant_key)

    auth0_roles = auth0_permit_syncer.get_auth0_roles(auth0_domain)

    # get all roles from permit
    permit_roles = auth0_permit_syncer.get_all_roles_from_permit()
    # get all roles keys from permit
    permit_role_keys = [role.key for role in permit_roles] # type: ignore
    missing_roles = []
    for auth0_role in auth0_roles:
        if auth0_role['name'] not in permit_role_keys:
            missing_roles.append(auth0_role['name'])
    if len(missing_roles) > 0:
        print(f"Missing roles in permit: {missing_roles}")
        print("Do you want to create them?")
        answer = input("y/n: ")
        if answer == 'y':
            # create missing roles in permit
            auth0_permit_syncer.create_missing_roles_in_permit(missing_roles)
        else:
            exit(f"Create those: '{missing_roles}' roles in permit and run the script again")
    else:
        print("All roles are in permit")
        auth0_permit_syncer.sync_users()
        


@click.command()
@click.option('--csv_file', prompt='All users export CSV file path', help='CSV file path, needs to have the following columns: email, user_id, given_name, family_name')
@click.option('--tenant_key', prompt='Tenant key', help='Tenant key', default='default')
@click.pass_context
def get_consts(*args, **kwargs):
    csv_file = kwargs['csv_file']
    tenant_key = kwargs['tenant_key']
    main(csv_file, tenant_key)


if __name__ == '__main__':
    # get consts and init them in the class
    try:
        csv_file, tenant_key = get_consts()
    except Exception as e:
        print(e)
        exit(1)
