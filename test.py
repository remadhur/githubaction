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
print(TF_VAR_TENANT_ID)
