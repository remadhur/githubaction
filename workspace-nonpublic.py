""""workspace-nonpublic.py - Set an AzureML workspace to private via API.
This script requires a service principal with the rights to read and update
the Workspace. It is referred to below as the "SP".
Environment variables required:
    * TENANT_ID - Tenant ID
    * SP_CLIENT_ID - SP client ID
    * SP_CLIENT_SECRET - SP client secret
Command line arguments to be specified (see also `python
workspace-nonpublic.py --help` or the main function below):
    * sub-id - Subscription ID containing the AzureML workspace
    * rg-name - Resource group name containing the AzureML workspace
    * ws-name - Name of AzureML workspace to make private
On every execution, this script verifies that the Terraform issue is still
open. If it is closed, then the script will refuse to run (since the Terraform
script can be updated and this hack can be removed).
Once that check is complete, the script will obtain an access token for the
SP and get the current config for the workspace. If the workspace property
publicNetworkAccess is NOT set to Disabled, then the script will update that
property (and only that property).
"""

import argparse
from distutils.util import subst_vars
import json
import logging
import os
import sys
from typing import Tuple
import urllib.request


def get_env(name: str, required: bool = True, default_val: str = ""):
    """Helper: get an environment variable which may be required and/or have a
    default value. By default, var is required.
    """
    val = os.environ.get(name, default_val)
    if required and not val:
        raise ValueError(f"{name} is a required environment variable")
    return val
##
TF_VAR_TENANT_ID = get_env("TF_VAR_TENANT_ID")
TF_VAR_APPLICATION_ID = get_env("TF_VAR_APPLICATION_ID")
TF_VAR_SP_SECRET = get_env("TF_VAR_SP_SECRET")
sub_id = get_env("TF_VAR_SUBSCRIPTION_ID")
rg_name = get_env("TF_RG_NAME")
ws_name = get_env("TF_WS_NAME")

def do_request(request: urllib.request.Request) -> Tuple[int, str]:
    """Given a configured request, perform the request and return the status
    and body received
    """
    logging.info("%s: %s", request.method, request.full_url)

    opener = urllib.request.build_opener()
    with opener.open(request) as response:
        status = response.status
        charset = response.headers.get_content_charset("utf-8")
        body = response.read().decode(charset)

    return status, body


def issue_open() -> bool:
    """Figure out if the problem we are working around it still open and
    unsolved. Return true if so (and we should proceeed with out hack.
    """

    ISSUE = "hashicorp/terraform-provider-azurerm/issues/16177"

    status, body = do_request(
        urllib.request.Request(
            f"https://api.github.com/repos/{ISSUE}",
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
            },
        )
    )

    if status != 200:
        logging.warning("Could not check %s: assuming it is still open", ISSUE)
        return True

    try:
        issue = json.loads(body)
        state = issue.get("state", "missing").strip().lower()
    except:
        logging.exception(
            "Could not parse GitHub response: will assume %s is open", ISSUE
        )
        return True

    if state == "open":
        logging.info("%s is still open", ISSUE)
        return True
    elif state == "closed":
        logging.error("%s is closed - we should no longer be using this workaround!!!")
        return False
    else:
        logging.warning(
            "Can not determine %s state (found %s) - assuming open", ISSUE, state
        )
        return True


def get_token() -> str:
    """Get Azure OAuth2 token for API calls"""
    url = f"https://login.microsoftonline.com/{TF_VAR_TENANT_ID}/oauth2/token"
    req_body = "&".join(
        [
            "grant_type=client_credentials",
            "resource=https%3A%2F%2Fmanagement.azure.com%2F",
            f"client_id={TF_VAR_APPLICATION_ID}",
            f"client_secret={TF_VAR_SP_SECRET}",
        ]
    )

    status, resp_body = do_request(
        urllib.request.Request(
            url,
            method="POST",
            data=req_body.encode(),
            headers={
                "Accept": "*/*",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
    )

    if status != 200:
        raise ValueError(f"Could not get token. Resp was {status}:{resp_body}")

    token = json.loads(resp_body)
    access_token = token.get("access_token", "")
    if not access_token:
        raise ValueError("Could not find access_token in response")

    expire_mins = int(token.get("expires_in", "0")) / 60.0
    if expire_mins < 0.01:
        logging.warning("Have a token but could not find expiration time")
    else:
        logging.info("Have a token: it expires in %.1f mins", expire_mins)

    return access_token


def update_workspace(access_token: str, sub_id: str, rg_name: str, ws_name: str):
    """Given a workspace name and a token, update it to be private"""
    ws_url = f"https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{rg_name}/providers/Microsoft.MachineLearningServices/workspaces/{ws_name}?api-version=2022-05-01"

    status, resp_body = do_request(
        urllib.request.Request(
            ws_url,
            method="GET",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )
    )
    if status != 200:
        raise ValueError(
            f"Could not find the requested workspace {ws_name}. Resp was {status}:{resp_body}"
        )

    ws = json.loads(resp_body)
    ws_id = ws.get("id", ws_name)
    pub_access = ws.get("properties", {}).get("publicNetworkAccess", "").strip().lower()
    if pub_access == "disabled":
        logging.info(
            "No work to do: properties.publicNetworkAccess already disabled for %s",
            ws_id,
        )
        return
    elif pub_access == "enabled":
        logging.info(
            "properties.publicNetworkAccess enabled - will set to disabled for %s",
            ws_id,
        )
    else:
        logging.warning(
            "Do not understand properties.publicNetworkAccess=%s - attempting disable for %s",
            pub_access,
            ws_id,
        )

    req_body = {"properties": {"publicNetworkAccess": "Disabled"}}

    status, resp_body = do_request(
        urllib.request.Request(
            ws_url,
            method="PATCH",
            data=json.dumps(req_body).encode(),
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json; charset=UTF-8",
                "Accept": "application/json",
            },
        )
    )

    if status not in {200, 202}:
        raise ValueError(f"Could not update {ws_name}. Received {status}:{resp_body}")

    logging.info("Updated %s", ws_name)


def main():
    """Entry point"""
    p = argparse.ArgumentParser()
    p.add_argument(
        "--sub-id",
        required=True,
        help="Subscription ID containing the AzureML workspace",
    )
    p.add_argument(
        "--rg-name",
        required=True,
        help="Resource group name containing the AzureML workspace",
    )
    p.add_argument(
        "--ws-name", required=True, help="Name of AzureML workspace to make private"
    )
    args = p.parse_args()

    if not issue_open():
        raise ValueError("FIX THE PIPELINE - STOP THE WORKAROUND")

    update_workspace(get_token(), args.sub_id, args.rg_name, args.ws_name)


def logging_init():
    """Helper: set up logging for this script"""
    formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s")
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        handlers=[
            handler,
        ],
        datefmt="%Y-%m-%d %H:%M:%S",
    )


if __name__ == "__main__":
    try:
        exit_code = 0
        logging_init()
        main()
    except:
        logging.exception("Unhandled exception during processing")
        exit_code = 1
    finally:
        logging.shutdown()
    sys.exit(exit_code)