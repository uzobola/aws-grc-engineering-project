import boto3


def create_aws_session(profile_name: str, region_name: str) -> boto3.Session:
    """
    Creates a boto3 session using a named AWS CLI profile.

    This keeps the evidence collector tied to an intentional AWS profile
    instead of relying on the default profile.
    """
    return boto3.Session(
        profile_name=profile_name,
        region_name=region_name
    )
