from enum import Enum


class SetupStep(str, Enum):
    welcome = "welcome"
    check_veracrypt = "check_veracrypt"
    detect_hardware = "detect_hardware"
    enroll_fingerprint = "enroll_fingerprint"
    create_workspace = "create_workspace"
    provision_secret = "provision_secret"
    setup_recovery = "setup_recovery"
    finish = "finish"
