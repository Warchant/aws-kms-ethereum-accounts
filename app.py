#!/usr/bin/env python3

#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#  SPDX-License-Identifier: MIT-0

from aws_cdk import App

from aws_kms_lambda_bitcoin.aws_kms_lambda_ethereum_stack import (
    AwsKmsLambdaBitcoinStack,
)

app = App()
AwsKmsLambdaBitcoinStack(app, "aws-kms-lambda-bitcoin")

app.synth()
