#!/usr/bin/python3

import pexpect
from getpass import getpass

child = pexpect.spawn("sudo -i")
pw = getpass("请输入密码：")
child.sendline(f"{pw}\n")
child.expect("# ")
child.sendline("rm -rf /etc/LICENSE /etc/.kyinfo\n")
child.expect("# ")
