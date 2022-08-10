import os
print("testing python")
def get_env(name: str, required: bool = True, default_val: str = ""):
    """Helper: get an environment variable which may be required and/or have a
    default value. By default, var is required.
    """
    val = os.environ.get(name, default_val)
    if required and not val:
        raise ValueError(f"{name} is a required environment variable")
    return val
TF_VAR_TENANT_ID = get_env("TF_VAR_TENANT_ID")
TF_VAR_TENANT_ID = get_env("TF_VAR_TENANT_ID")
TF_VAR_APPLICATION_ID = get_env("TF_VAR_APPLICATION_ID")
TF_VAR_SP_SECRET = get_env("TF_VAR_SP_SECRET")
sub_id = get_env("TF_VAR_SUBSCRIPTION_ID")
rg_name = get_env("TF_RG_NAME")
rg_name = get_env("TF_WS_NAME")
print(rg_name)
print(rg_name)
