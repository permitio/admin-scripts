# admin-scripts

Here you can find scripts to help you manage your Permit.io account.

In the Auth0 folder, you can find the script to sync your Auth0 users to Permit.io

You can follow the instructions on this page https://docs.permit.io/integrations/authentication/auth0/auth0-sync-script

To run this code run the following commands:

```bash
//enter to auth0 folder
cd auth0
//Make sure you have Python installed, if you don't have Python install it from https://www.python.org/downloads/
//Install the requirements by running this command
pip install -r requirements.txt
// add those following env variables AUTH0_DOMAIN AUTH0_MGMT_ACCESS_TOKEN PERMIT_SDK_TOKEN


// run the script with the csv_file param (you can also add the tenant key that you want those users to be part of with: --tenant_key <permit_tenant_key>
python auth0_sync_users_with_permit.py --csv_file <path_to_the_auth0_exported_users_file>
```
