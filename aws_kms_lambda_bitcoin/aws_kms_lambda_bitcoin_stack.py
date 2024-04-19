from aws_cdk import (
    Stack,
    Duration,
    CfnOutput,
    BundlingOptions,
    RemovalPolicy,
    aws_lambda,
    aws_kms,
    DockerImage,
)
from constructs import Construct


class MyLambda(Construct):
    def __init__(self, scope: Construct, id: str, dir: str, env: dict):
        super().__init__(scope, id)

        commands = [
            "if [[ -f requirements.txt ]]; then pip install --target /asset-output -r requirements.txt; fi",
            "cp --parents $(find . -name '*.py') /asset-output",
        ]

        bundling_config = BundlingOptions(
            image=DockerImage("public.ecr.aws/sam/build-python3.9:latest-x86_64"),
            command=["bash", "-xe", "-c", " && ".join(commands)],
        )

        code = aws_lambda.Code.from_asset(path=dir, bundling=bundling_config)

        lf = aws_lambda.Function(
            self,
            "Function",
            handler="lambda_function.lambda_handler",
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            environment=env,
            timeout=Duration.minutes(1),
            code=code,
            memory_size=128,
        )

        self.lf = lf


class AwsKmsLambdaBitcoinStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        cmk = aws_kms.Key(
            self, "btc-cmk-identity", removal_policy=RemovalPolicy.DESTROY
        )
        cfn_cmk = cmk.node.default_child
        cfn_cmk.key_spec = "ECC_SECG_P256K1"
        cfn_cmk.key_usage = "SIGN_VERIFY"

        eth_client = MyLambda(
            self,
            "btc-kms-client",
            dir="aws_kms_lambda_bitcoin/_lambda/functions/btc_signer",
            env={
                "LOG_LEVEL": "DEBUG",
                "KMS_KEY_ID": cmk.key_id,
                # Bohdan: for production env set this to hexencoded random 32 bytes (16+ bytes would be enough)
                # for testing, value "skip" skips HMAC verification
                "HMAC_KEY": "skip",
            },
        )

        cmk.grant(eth_client.lf, "kms:GetPublicKey")
        cmk.grant(eth_client.lf, "kms:Sign")

        CfnOutput(
            self,
            "KeyID",
            value=cmk.key_id,
            description="KeyID of the KMS-CMK instance used as the Bitcoin identity instance",
        )
