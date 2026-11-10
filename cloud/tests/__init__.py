"""Tests of the StepCheck Cloud service.

This directory is a package on purpose: pytest then puts the repository root on the
import path (so `cloud` and the engine resolve) and names the module
`cloud.tests.test_cloud_mvp`. A `conftest.py` here would shadow the one in
`backend/tests`, which those tests import by its bare name.
"""
